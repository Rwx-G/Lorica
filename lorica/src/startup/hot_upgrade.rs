// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Zero-downtime hot binary-upgrade handoff (Story 8.4 chunk 2).
//!
//! # Why this works with zero dropped connections
//!
//! The old supervisor keeps long-lived `dup`s of its proxy listening
//! sockets (see `WorkerManager::handoff_listen_fds`). On upgrade it serves
//! those exact FDs to a freshly exec'd new supervisor over a Unix socket
//! (`<data_dir>/upgrade/transfer.sock`) using `lorica_core`'s `Fds`
//! SCM_RIGHTS machinery. The new supervisor hands the SAME kernel
//! listening sockets to its own workers. Because both processes' workers
//! now `accept` from the same single kernel accept queue, every incoming
//! connection is delivered to exactly one of them - there is ALWAYS an
//! acceptor during the overlap, so no connection is dropped. The old
//! process only stops accepting (and closes its copies) AFTER it has
//! drained its in-flight worker connections, on the success path; on the
//! rollback path it never stops accepting at all.
//!
//! # The handshake
//!
//! 1. Old: spawn a task serving the listener FDs on `transfer.sock`.
//! 2. Old: bind a Unix datagram readiness socket `ready.sock`, then
//!    `fork`+`execv` the staged `lorica.new` with `--hot-upgrade`.
//! 3. New: pull the FDs from `transfer.sock`, build its workers from
//!    them, start accepting + the management API, then run the readiness
//!    handshake: bind `ack.sock`, and repeatedly send a "ready" datagram
//!    to `ready.sock` until it receives an "ack" back (or its deadline
//!    elapses, in which case it exits so the old rolls back cleanly).
//! 4. Old: wait up to 10 s for the readiness datagram while watching the
//!    child for an early exit. On ready -> ack the new side, drain
//!    workers, record the metrics, exit(0). On early exit / timeout ->
//!    roll back (kill the child, quarantine the staged binary, resume).
//! 5. New: only AFTER the ack does it `sd_notify` `READY=1` +
//!    `MAINPID=<newpid>` (systemd main-PID handover) and record the
//!    terminal `completed` outcome. Deferring the MAINPID reassignment
//!    until the old has committed to draining is what prevents a lost
//!    readiness datagram from stranding systemd on a killed PID (H3).

use std::os::fd::RawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use lorica_core::server::Fds;

/// Deadline for the freshly exec'd supervisor to signal readiness before
/// the old side rolls back (Story 8.4 AC #6).
pub const READY_DEADLINE: Duration = Duration::from_secs(10);

/// Deadline for the NEW supervisor to get an ack back from the old before
/// it gives up and exits so the old rolls back. Set slightly above
/// [`READY_DEADLINE`]: if the old is going to ack at all it does so within
/// its own readiness window, and the new must not give up first (audit H3).
pub const READY_ACK_DEADLINE: Duration = Duration::from_secs(12);

/// Datagram an up new supervisor sends to the old over `ready.sock`.
const READY_TOKEN: &[u8] = b"ready";

/// Datagram the old supervisor sends back over `ack.sock` to confirm it
/// received the readiness signal and has committed to draining. The new
/// side waits for this before reassigning the systemd MAINPID, so a lost
/// readiness datagram can never leave the old rolling back (SIGKILLing the
/// new) after the new already claimed MAINPID (audit H3 split-brain).
const ACK_TOKEN: &[u8] = b"ack";

/// Restrict a just-bound Unix socket to owner-only (0600). Defence in
/// depth on top of the 0700 `upgrade/` directory: the handoff sockets
/// carry live listening-socket FDs and the MAINPID handshake, so no other
/// local user should be able to reach them even if the directory mode
/// were ever relaxed (audit L1/L2). Best-effort: a chmod failure is logged
/// and the directory mode remains the primary control.
fn restrict_socket_perms(path: &Path) {
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        tracing::warn!(path = %path.display(), error = %e, "hot upgrade: could not tighten socket perms to 0600");
    }
}

/// `Fds` table key prefix marking the management-API listener, so the
/// new supervisor can tell it apart from the proxy (HTTP/HTTPS) listeners
/// after pulling the FD set. The proxy listeners are keyed by their bind
/// address (e.g. `0.0.0.0:8080`) so the worker manager can re-tag them.
const MANAGEMENT_KEY_PREFIX: &str = "management:";

/// `Fds` table key prefix for the cluster-plane listener (Story 9.1
/// AC #7). The listener itself arrives with Story 9.2's
/// `--cluster-listen`; the handoff seam is extended here first so the
/// FD-transfer wire format is settled before any cluster deployment
/// exists, and a control-plane node never loses its accept queue
/// across a hot binary upgrade.
const CLUSTER_KEY_PREFIX: &str = "cluster:";

/// `Fds` table key for the cluster listener bound at `bind_addr`.
pub fn cluster_fds_key(bind_addr: &str) -> String {
    format!("{CLUSTER_KEY_PREFIX}{bind_addr}")
}

/// `<data_dir>/upgrade` - the operator-only staging directory shared with
/// the verify+stage path in `lorica_api::upgrade`.
pub fn upgrade_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("upgrade")
}

/// Path of the Unix socket the old supervisor serves listener FDs on and
/// the new one pulls them from.
pub fn transfer_sock_path(data_dir: &Path) -> PathBuf {
    upgrade_dir(data_dir).join("transfer.sock")
}

/// Path of the Unix datagram socket the old supervisor binds to receive
/// the new supervisor's readiness signal.
pub fn ready_sock_path(data_dir: &Path) -> PathBuf {
    upgrade_dir(data_dir).join("ready.sock")
}

/// Path of the Unix datagram socket the NEW supervisor binds to receive
/// the old supervisor's ack of its readiness signal (audit H3).
pub fn ack_sock_path(data_dir: &Path) -> PathBuf {
    upgrade_dir(data_dir).join("ack.sock")
}

/// Quarantine name for a staged binary whose handoff failed:
/// `<data_dir>/upgrade/lorica.failed.<unix_ts>`.
pub fn failed_binary_path(data_dir: &Path, unix_ts: u64) -> PathBuf {
    upgrade_dir(data_dir).join(format!("lorica.failed.{unix_ts}"))
}

/// `Fds` table key for the management listener on `port`.
pub fn management_fds_key(port: u16) -> String {
    format!("{MANAGEMENT_KEY_PREFIX}127.0.0.1:{port}")
}

/// Why a handoff rolled back, mapped 1:1 to a
/// `lorica_hot_upgrade_total{outcome=...}` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackReason {
    /// The new process exited before signalling ready, or never signalled
    /// ready within [`READY_DEADLINE`].
    ExecFailed,
    /// The connection drain on the (otherwise successful) handoff exceeded
    /// its window and stragglers were force-killed.
    DrainTimeout,
}

impl RollbackReason {
    /// Metric `outcome` label for this reason.
    pub fn metric_outcome(self) -> &'static str {
        match self {
            RollbackReason::ExecFailed => "exec_failed",
            RollbackReason::DrainTimeout => "drain_timeout",
        }
    }
}

/// Verdict of the readiness wait: drain the old process or roll back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffDecision {
    /// The new process is accepting: drain the old workers and exit.
    Drain,
    /// The new process failed to come up: roll back and keep serving.
    Rollback(RollbackReason),
}

/// Pure decision function for the readiness wait loop (unit-tested).
///
/// Returns `None` while the wait should continue, or `Some(decision)`
/// once a terminal state is reached:
/// - new signalled ready -> [`HandoffDecision::Drain`];
/// - child no longer alive -> rollback ([`RollbackReason::ExecFailed`]);
/// - deadline reached without readiness -> rollback (`ExecFailed`).
///
/// Readiness is checked first so a child that signals ready and then
/// exits in the same instant is still treated as up.
pub fn decide_readiness(
    new_ready: bool,
    child_alive: bool,
    elapsed: Duration,
    deadline: Duration,
) -> Option<HandoffDecision> {
    if new_ready {
        return Some(HandoffDecision::Drain);
    }
    if !child_alive {
        return Some(HandoffDecision::Rollback(RollbackReason::ExecFailed));
    }
    if elapsed >= deadline {
        return Some(HandoffDecision::Rollback(RollbackReason::ExecFailed));
    }
    None
}

/// `sd_notify` payload reassigning the systemd unit's main PID to the new
/// supervisor and marking it ready. Hand-rolled (no crate) - the wire
/// format is newline-separated `KEY=VALUE` pairs.
pub fn notify_payload(main_pid: i32) -> String {
    format!("READY=1\nMAINPID={main_pid}\n")
}

/// Listener FDs pulled from an outgoing supervisor during a hot upgrade.
pub struct InheritedListeners {
    /// Proxy listeners keyed by bind address (HTTP, optionally HTTPS).
    pub proxy: Vec<(String, RawFd)>,
    /// The management-API listener FD, if it was handed over.
    pub management: Option<RawFd>,
    /// The cluster-plane listener (bind address, FD), if the outgoing
    /// supervisor ran with `--cluster-listen` (Story 9.1 AC #7; the
    /// listener itself lands in Story 9.2).
    pub cluster: Option<(String, RawFd)>,
}

/// Build the `Fds` table the old supervisor serves: every proxy listener
/// keyed by its bind address, the management listener under the
/// [`MANAGEMENT_KEY_PREFIX`] key, and the cluster listener (when
/// present) under the [`CLUSTER_KEY_PREFIX`] key.
fn build_fds_table(
    proxy: &[(String, RawFd)],
    management_fd: RawFd,
    management_port: u16,
    cluster: Option<&(String, RawFd)>,
) -> Fds {
    let mut fds = Fds::new();
    for (addr, fd) in proxy {
        fds.add(addr.clone(), *fd);
    }
    fds.add(management_fds_key(management_port), management_fd);
    if let Some((bind, fd)) = cluster {
        fds.add(cluster_fds_key(bind), *fd);
    }
    fds
}

/// Serve the listening-socket FDs on `transfer.sock` (BLOCKING).
///
/// Runs on a blocking thread (the underlying `send_to_sock` uses
/// `thread::sleep` for its connect/send retry budget). Returns once the
/// new supervisor has connected and pulled the FDs, or on error/timeout.
pub fn serve_listener_fds_blocking(
    data_dir: &Path,
    proxy: &[(String, RawFd)],
    management_fd: RawFd,
    management_port: u16,
    cluster: Option<&(String, RawFd)>,
) -> Result<(), String> {
    let table = build_fds_table(proxy, management_fd, management_port, cluster);
    let sock = transfer_sock_path(data_dir);
    let sock_str = sock.to_string_lossy().into_owned();
    table
        .send_to_sock(sock_str.as_str())
        .map(|_sent| ())
        .map_err(|e| format!("failed to serve listener FDs on {sock_str}: {e}"))
}

/// Pull the inherited listening sockets from `transfer.sock` (BLOCKING).
///
/// Called by the NEW supervisor before it starts its tokio runtime,
/// mirroring the bind-then-fork ordering of a fresh start. Partitions the
/// pulled FD set into proxy listeners, the management listener, and the
/// cluster listener.
pub fn pull_inherited_listeners(
    data_dir: &Path,
    management_port: u16,
) -> Result<InheritedListeners, String> {
    let sock = transfer_sock_path(data_dir);
    let sock_str = sock.to_string_lossy().into_owned();

    let mut fds = Fds::new();
    fds.get_from_sock(sock_str.as_str())
        .map_err(|e| format!("failed to pull inherited listeners from {sock_str}: {e}"))?;

    let (serialized_keys, serialized_fds) = fds.serialize();
    Ok(partition_inherited_fds(
        serialized_keys,
        serialized_fds,
        management_port,
    ))
}

/// Partition a pulled FD table into proxy / management / cluster
/// listeners by key prefix. Pure (no socket ops), so the wire-format
/// partitioning is unit-testable without an SCM_RIGHTS round-trip.
fn partition_inherited_fds(
    keys: Vec<String>,
    fds: Vec<RawFd>,
    management_port: u16,
) -> InheritedListeners {
    let management_key = management_fds_key(management_port);
    let mut proxy: Vec<(String, RawFd)> = Vec::new();
    let mut management: Option<RawFd> = None;
    let mut cluster: Option<(String, RawFd)> = None;
    for (key, fd) in keys.into_iter().zip(fds) {
        if key == management_key || key.starts_with(MANAGEMENT_KEY_PREFIX) {
            management = Some(fd);
        } else if let Some(bind) = key.strip_prefix(CLUSTER_KEY_PREFIX) {
            cluster = Some((bind.to_string(), fd));
        } else {
            proxy.push((key, fd));
        }
    }
    InheritedListeners {
        proxy,
        management,
        cluster,
    }
}

/// NEW-side readiness handshake: repeatedly announce readiness to the old
/// supervisor on `ready.sock` and wait for its ack on `ack.sock`, up to
/// `deadline`. Returns `Ok(true)` once acked, `Ok(false)` if the deadline
/// elapses with no ack.
///
/// This is the robust half of audit H3: the caller (new supervisor) must
/// NOT reassign the systemd MAINPID until this returns `true`. A single
/// dropped readiness datagram no longer strands the handoff - the new side
/// keeps resending until the old acks (or gives up and exits so the old
/// rolls back cleanly, having never lost MAINPID).
pub async fn handshake_ready_with_old(
    data_dir: &Path,
    deadline: Duration,
) -> std::io::Result<bool> {
    let ack_path = ack_sock_path(data_dir);
    let _ = std::fs::remove_file(&ack_path);
    let sock = tokio::net::UnixDatagram::bind(&ack_path)?;
    restrict_socket_perms(&ack_path);

    let ready_path = ready_sock_path(data_dir);
    let start = Instant::now();
    let mut buf = [0u8; 64];
    while start.elapsed() < deadline {
        // (Re)announce readiness; ignore transient send errors (the old
        // may not have bound ready.sock in the same instant).
        let _ = sock.send_to(READY_TOKEN, &ready_path).await;
        match tokio::time::timeout(Duration::from_millis(200), sock.recv(&mut buf)).await {
            Ok(Ok(n)) if buf.get(..n) == Some(ACK_TOKEN) => {
                let _ = std::fs::remove_file(&ack_path);
                return Ok(true);
            }
            // Timeout tick or a spurious datagram: resend and keep waiting.
            _ => {}
        }
    }
    let _ = std::fs::remove_file(&ack_path);
    Ok(false)
}

/// OLD-side ack burst: fire several `ACK_TOKEN` datagrams at the new
/// supervisor's `ack.sock`. Called the instant a readiness datagram
/// arrives, before the old commits to draining. The new side stops
/// resending on the first ack it receives, so a short burst on loopback
/// (where a bound, actively-receiving peer effectively never drops)
/// reliably delivers at least one even if an individual datagram is lost
/// (audit H3).
async fn send_ack_burst(ack_target: &Path) {
    let Ok(sock) = tokio::net::UnixDatagram::unbound() else {
        return;
    };
    for _ in 0..10 {
        if sock.send_to(ACK_TOKEN, ack_target).await.is_err() {
            // ack.sock not bound yet or gone; a later tick may still land.
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Send the `sd_notify` `READY=1` + `MAINPID` datagram to `$NOTIFY_SOCKET`
/// (NEW side). Returns `Ok(true)` when sent, `Ok(false)` when
/// `$NOTIFY_SOCKET` is unset (not under systemd: Docker, manual run) so
/// the caller can log "skipped" rather than error.
///
/// Abstract sockets (`$NOTIFY_SOCKET` beginning with `@`) are not
/// supported on stable std and are skipped with `Ok(false)`; systemd's
/// default is a filesystem path, which is handled.
pub fn sd_notify_ready(main_pid: i32) -> std::io::Result<bool> {
    let Some(socket_path) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(false);
    };
    let path = PathBuf::from(&socket_path);
    if path.as_os_str().to_string_lossy().starts_with('@') {
        return Ok(false);
    }
    let dgram = std::os::unix::net::UnixDatagram::unbound()?;
    dgram.send_to(notify_payload(main_pid).as_bytes(), &path)?;
    Ok(true)
}

/// Quarantine a staged binary whose handoff failed by renaming it to
/// `lorica.failed.<unix_ts>` so a retry stages a fresh `lorica.new` and
/// the failed image is preserved for inspection (Story 8.4 AC #6).
pub fn quarantine_failed_binary(
    data_dir: &Path,
    staged_path: &Path,
    unix_ts: u64,
) -> std::io::Result<PathBuf> {
    let dest = failed_binary_path(data_dir, unix_ts);
    std::fs::rename(staged_path, &dest)?;
    Ok(dest)
}

/// Await the new supervisor's readiness on `ready_listener` (a bound Unix
/// datagram socket), polling the child PID for an early exit and honoring
/// `deadline`.
///
/// Polls in short ticks so child-liveness is re-checked even while no
/// datagram arrives. The terminal verdict comes from [`decide_readiness`].
/// On the first readiness datagram it fires an ack burst at `ack_target`
/// (the new side's `ack.sock`) so the new supervisor can safely reassign
/// the systemd MAINPID; only THEN does this return [`HandoffDecision::Drain`]
/// (audit H3). No ack is sent on the rollback paths.
pub async fn wait_for_new_ready(
    ready_listener: &tokio::net::UnixDatagram,
    ack_target: &Path,
    child: lorica_worker::Pid,
    deadline: Duration,
) -> HandoffDecision {
    let start = Instant::now();
    let mut new_ready = false;
    let mut buf = [0u8; 64];
    loop {
        match tokio::time::timeout(
            Duration::from_millis(200),
            ready_listener.recv(&mut buf),
        )
        .await
        {
            Ok(Ok(n)) if buf.get(..n) == Some(READY_TOKEN) => {
                if !new_ready {
                    // First readiness signal: ack it so the new side can
                    // take over MAINPID before we drain and exit.
                    send_ack_burst(ack_target).await;
                }
                new_ready = true;
            }
            // Other datagram, recv error, or tick timeout: re-check the
            // child + deadline and keep waiting.
            _ => {}
        }
        let child_alive = !lorica_worker::hot_upgrade::child_exited(child);
        if let Some(decision) =
            decide_readiness(new_ready, child_alive, start.elapsed(), deadline)
        {
            return decision;
        }
    }
}

/// Inputs to [`run_old_side_handoff`].
pub struct HandoffArgs {
    /// Lorica data directory (holds the `upgrade/` working files).
    pub data_dir: PathBuf,
    /// Staged, verified new binary to exec (`upgrade/lorica.new`).
    pub staged_binary: PathBuf,
    /// Proxy listening sockets to hand over, keyed by bind address.
    pub proxy_fds: Vec<(String, RawFd)>,
    /// Management-API listening socket to hand over.
    pub management_fd: RawFd,
    /// Management port (used to key the management FD in the table).
    pub management_port: u16,
    /// Cluster-plane listener (bind address, FD) to hand over, when
    /// the node runs with `--cluster-listen` (Story 9.1 AC #7; wired
    /// by Story 9.2, always `None` until then).
    pub cluster_fd: Option<(String, RawFd)>,
    /// Full argv for the new binary, `argv[0]` first.
    pub child_argv: Vec<String>,
}

/// Result of the old-side handoff up to the readiness decision.
pub struct HandoffRun {
    /// Drain-or-rollback verdict.
    pub decision: HandoffDecision,
    /// PID of the exec'd new supervisor, if the fork succeeded. The
    /// caller SIGKILLs it on rollback and lets it run on success.
    pub child: Option<lorica_worker::Pid>,
    /// The blocking task serving the listener FDs. The caller aborts it
    /// on rollback; on success it has already completed (FDs pulled).
    pub serve_task: tokio::task::JoinHandle<Result<(), String>>,
}

/// Drive the outgoing supervisor's side of the handoff: serve the
/// listening sockets, fork+exec the staged binary, and wait for it to
/// signal readiness (or fail) within [`READY_DEADLINE`].
///
/// Returns once a [`HandoffDecision`] is reached. This function performs
/// NO drain and NO teardown: the caller owns the worker manager and the
/// background-task tracker, so it runs the drain (on `Drain`) or the
/// quarantine + child kill (on `Rollback`) with that state in scope.
pub async fn run_old_side_handoff(args: HandoffArgs) -> HandoffRun {
    // Bind the readiness datagram socket BEFORE forking the child so a
    // very fast new process cannot send "ready" before we are listening.
    let ready_path = ready_sock_path(&args.data_dir);
    let _ = std::fs::remove_file(&ready_path);
    let ready_listener = match tokio::net::UnixDatagram::bind(&ready_path) {
        Ok(l) => {
            restrict_socket_perms(&ready_path);
            l
        }
        Err(e) => {
            // Cannot observe readiness: spawn a no-op completed serve task
            // so the return type holds, and roll back.
            let serve_task = tokio::task::spawn_blocking(move || -> Result<(), String> {
                Err(format!("readiness socket bind failed: {e}"))
            });
            return HandoffRun {
                decision: HandoffDecision::Rollback(RollbackReason::ExecFailed),
                child: None,
                serve_task,
            };
        }
    };

    // Serve the listener FDs on the transfer socket (blocking; the new
    // process connects and pulls them).
    let serve_data_dir = args.data_dir.clone();
    let serve_proxy = args.proxy_fds.clone();
    let serve_mgmt = args.management_fd;
    let serve_port = args.management_port;
    let serve_cluster = args.cluster_fd.clone();
    let serve_task = tokio::task::spawn_blocking(move || {
        serve_listener_fds_blocking(
            &serve_data_dir,
            &serve_proxy,
            serve_mgmt,
            serve_port,
            serve_cluster.as_ref(),
        )
    });

    // Fork + exec the staged binary.
    let exe = args.staged_binary.to_string_lossy().into_owned();
    let child = match lorica_worker::hot_upgrade::fork_exec(&exe, &args.child_argv) {
        Ok(pid) => pid,
        Err(e) => {
            tracing::error!(error = %e, "hot upgrade: fork/exec of staged binary failed");
            return HandoffRun {
                decision: HandoffDecision::Rollback(RollbackReason::ExecFailed),
                child: None,
                serve_task,
            };
        }
    };
    tracing::info!(child_pid = child.as_raw(), "hot upgrade: forked new supervisor, awaiting readiness");

    let ack_target = ack_sock_path(&args.data_dir);
    let decision = wait_for_new_ready(&ready_listener, &ack_target, child, READY_DEADLINE).await;
    // Clean up the readiness socket regardless of outcome (the new side
    // owns and removes ack.sock).
    let _ = std::fs::remove_file(&ready_path);

    HandoffRun {
        decision,
        child: Some(child),
        serve_task,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_routes_cluster_listener_by_prefix() {
        // Story 9.1 AC #7: the FD-transfer wire format carries an
        // optional cluster listener alongside proxy + management, and
        // the new supervisor partitions it back out by key prefix.
        let keys = vec![
            "0.0.0.0:8080".to_string(),
            "0.0.0.0:8443".to_string(),
            management_fds_key(9443),
            cluster_fds_key("10.0.0.10:7443"),
        ];
        let fds: Vec<RawFd> = vec![10, 11, 12, 13];
        let inherited = partition_inherited_fds(keys, fds, 9443);
        assert_eq!(inherited.proxy.len(), 2);
        assert_eq!(inherited.management, Some(12));
        assert_eq!(inherited.cluster, Some(("10.0.0.10:7443".to_string(), 13)));

        // Without a cluster key the slot stays empty (every pre-9.2
        // deployment).
        let inherited = partition_inherited_fds(
            vec!["0.0.0.0:8080".to_string(), management_fds_key(9443)],
            vec![20, 21],
            9443,
        );
        assert!(inherited.cluster.is_none());
        assert_eq!(inherited.management, Some(21));
    }

    #[test]
    fn notify_payload_is_well_formed() {
        assert_eq!(notify_payload(4321), "READY=1\nMAINPID=4321\n");
    }

    #[test]
    fn rollback_reason_metric_labels() {
        assert_eq!(RollbackReason::ExecFailed.metric_outcome(), "exec_failed");
        assert_eq!(RollbackReason::DrainTimeout.metric_outcome(), "drain_timeout");
    }

    #[test]
    fn decide_ready_drains_even_if_child_just_exited() {
        // Readiness wins over a same-instant child exit.
        assert_eq!(
            decide_readiness(true, false, Duration::from_secs(1), READY_DEADLINE),
            Some(HandoffDecision::Drain)
        );
    }

    #[test]
    fn decide_child_gone_rolls_back_before_deadline() {
        assert_eq!(
            decide_readiness(false, false, Duration::from_secs(1), READY_DEADLINE),
            Some(HandoffDecision::Rollback(RollbackReason::ExecFailed))
        );
    }

    #[test]
    fn decide_deadline_exceeded_rolls_back() {
        assert_eq!(
            decide_readiness(false, true, Duration::from_secs(10), READY_DEADLINE),
            Some(HandoffDecision::Rollback(RollbackReason::ExecFailed))
        );
    }

    #[test]
    fn decide_keeps_waiting_while_alive_and_in_window() {
        assert_eq!(
            decide_readiness(false, true, Duration::from_secs(2), READY_DEADLINE),
            None
        );
    }

    #[test]
    fn failed_binary_path_includes_timestamp() {
        let p = failed_binary_path(Path::new("/var/lib/lorica"), 1_700_000_000);
        assert_eq!(
            p,
            PathBuf::from("/var/lib/lorica/upgrade/lorica.failed.1700000000")
        );
    }

    #[test]
    fn management_key_is_distinct_from_proxy_addrs() {
        let key = management_fds_key(9443);
        assert!(key.starts_with(MANAGEMENT_KEY_PREFIX));
        // Must not collide with a plausible proxy bind-address key.
        assert_ne!(key, "0.0.0.0:9443");
        assert_ne!(key, "127.0.0.1:9443");
    }

    #[test]
    fn transfer_and_ready_socks_live_under_upgrade_dir() {
        let d = Path::new("/data");
        assert_eq!(
            transfer_sock_path(d),
            PathBuf::from("/data/upgrade/transfer.sock")
        );
        assert_eq!(ready_sock_path(d), PathBuf::from("/data/upgrade/ready.sock"));
    }

    #[test]
    fn sd_notify_skips_when_socket_unset() {
        // SAFETY of the env mutation: this test does not run concurrently
        // with code that reads NOTIFY_SOCKET; it only asserts the unset
        // branch returns Ok(false).
        std::env::remove_var("NOTIFY_SOCKET");
        assert!(!sd_notify_ready(1234).unwrap());
    }
}
