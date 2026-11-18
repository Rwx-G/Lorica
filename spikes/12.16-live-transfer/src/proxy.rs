//! One generation of the proxy. Generation 0 binds; every later one is
//! exec'd by its predecessor with one end of a `SOCK_SEQPACKET` pair on
//! fd 3, pulls the listeners, the parked connections and the UDP sessions
//! over it, and takes over only once the old generation commits.
//!
//! The forwarding loop mirrors `lorica-stream/src/tcp/forward.rs`: one
//! fixed buffer per direction, one read then the whole chunk written
//! before the next read, so "both directions reading or closed" is the
//! point where no forwarded byte is held in userspace (the quiesce point
//! of the PRD).
//!
//! Handover protocol, old generation O, new generation N:
//!
//! 1. O spawns N; N sends `HELLO`.
//! 2. O stops accepting and stops reading the UDP slot socket, sends
//!    `LISTENERS`.
//! 3. O asks every forwarding connection to park and waits up to
//!    `transfer_timeout`. A connection parks by a compare-and-swap
//!    `PARK_REQ -> PARKED` at the quiesce point; at the deadline O swaps
//!    `PARK_REQ -> DRAIN`. Exactly one of the two wins.
//! 4. O sends one `TCP` message per parked connection (state + both
//!    sockets), one `UDP` message per session (state + upstream socket),
//!    then `END`.
//! 5. N answers `READY` (it holds everything, forwards nothing). O sends
//!    `COMMIT`. N answers `COMMITTED` and only then starts forwarding. O
//!    keeps its own descriptors until it reads `COMMITTED`.
//! 6. Failure: no `READY` in time, or EOF before `COMMITTED`: O kills and
//!    reaps N, then resumes everything it parked (it still holds the
//!    sockets, and N provably never forwarded). A `COMMIT` timeout is
//!    handled the same way, after the kill, by reading what N had queued:
//!    `COMMITTED` there means N forwarded, so O must not resume.
//!    N treats `ABORT` as "close what you received, never shut it down",
//!    and a bare EOF after `READY` (O died without deciding) as commit.

use std::collections::HashMap;
use std::io::{self, Write as _};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch, Notify};
use tokio::task::JoinHandle;

use crate::chan::{field, field_u64, Chan, Recv};
use crate::util::{arg, inq, mono_ns, outq, parse_args, shutdown_both, shutdown_write};

const RUN: u8 = 0;
const PARK_REQ: u8 = 1;
const PARKED: u8 = 2;
const DRAIN: u8 = 3;
const ENDED: u8 = 4;

const CONNECTING: u8 = 0;
const FORWARDING: u8 = 1;

const BUF: usize = 16 * 1024;

#[derive(Clone)]
pub struct Opts {
    pub raw: Vec<String>,
    pub gen: u32,
    pub attempt: u32,
    pub upgrades: u32,
    pub interval_ms: u64,
    pub transfer_timeout_ms: u64,
    pub ready_timeout_ms: i32,
    pub commit_timeout_ms: i32,
    pub idle_timeout_ms: u64,
    pub total_timeout_ms: u64,
    pub udp_idle_ms: u64,
    pub drain_ms: u64,
    pub dir: PathBuf,
    pub listen: SocketAddr,
    pub backend_tcp: SocketAddr,
    pub backend_udp: SocketAddr,
    pub crash_schedule: String,
    pub udp_naive: bool,
    pub abort_with_shutdown: bool,
    pub carry_held: bool,
    pub handover_fd: Option<RawFd>,
}

impl Opts {
    pub fn parse(args: &[String]) -> Opts {
        let m = parse_args(args);
        Opts {
            raw: args.to_vec(),
            gen: arg(&m, "gen", 0),
            attempt: arg(&m, "attempt", 0),
            upgrades: arg(&m, "upgrades", 0),
            interval_ms: arg(&m, "interval-ms", 200),
            transfer_timeout_ms: arg(&m, "transfer-timeout-ms", 1000),
            ready_timeout_ms: arg(&m, "ready-timeout-ms", 2000),
            commit_timeout_ms: arg(&m, "commit-timeout-ms", 2000),
            idle_timeout_ms: arg(&m, "idle-timeout-ms", 5_000),
            total_timeout_ms: arg(&m, "total-timeout-ms", 0),
            udp_idle_ms: arg(&m, "udp-idle-ms", 5000),
            drain_ms: arg(&m, "drain-ms", 30_000),
            dir: PathBuf::from(arg(&m, "dir", "/tmp/s1216".to_string())),
            listen: arg(&m, "listen", "127.0.0.1:9000".parse().unwrap()),
            backend_tcp: arg(&m, "backend-tcp", "127.0.0.1:9001".parse().unwrap()),
            backend_udp: arg(&m, "backend-udp", "127.0.0.1:9002".parse().unwrap()),
            crash_schedule: arg(&m, "crash-schedule", String::new()),
            udp_naive: arg(&m, "udp-naive", 0u8) == 1,
            abort_with_shutdown: arg(&m, "abort-with-shutdown", 0u8) == 1,
            carry_held: arg(&m, "carry-held", 0u8) == 1,
            handover_fd: m.get("handover-fd").and_then(|v| v.parse().ok()),
        }
    }

    /// The crash point a child of generation `gen`, attempt `attempt`,
    /// is told to hit. Only first attempts crash, so a retry succeeds.
    fn crash_for(&self, gen: u32, attempt: u32) -> Option<String> {
        if attempt != 0 {
            return None;
        }
        self.crash_schedule.split(',').find_map(|e| {
            let (g, point) = e.split_once(':')?;
            (g.parse::<u32>().ok()? == gen).then(|| point.to_string())
        })
    }

    /// The argv for a child: ours, without the per-process keys.
    fn child_args(&self, gen: u32, attempt: u32) -> Vec<String> {
        let mut out = Vec::new();
        let mut it = self.raw.iter();
        while let Some(k) = it.next() {
            let v = it.next().cloned().unwrap_or_default();
            if matches!(
                k.as_str(),
                "--gen" | "--attempt" | "--handover-fd" | "--crash-at"
            ) {
                continue;
            }
            out.push(k.clone());
            out.push(v);
        }
        out.extend([
            "--gen".into(),
            gen.to_string(),
            "--attempt".into(),
            attempt.to_string(),
            "--handover-fd".into(),
            "3".into(),
        ]);
        if let Some(p) = self.crash_for(gen, attempt) {
            out.extend(["--crash-at".into(), p]);
        }
        out
    }
}

/// Where one direction stands. Same states as Lorica's `DirectionState`
/// minus the PROXY-header classification.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DirSt {
    Reading,
    Writing { filled: usize, written: usize },
    Closed,
}

struct Dir {
    buf: Box<[u8]>,
    st: DirSt,
    bytes: u64,
}

impl Dir {
    fn new(st: DirSt, bytes: u64) -> Dir {
        Dir {
            buf: vec![0u8; BUF].into_boxed_slice(),
            st,
            bytes,
        }
    }
    fn at_rest(&self) -> bool {
        matches!(self.st, DirSt::Reading | DirSt::Closed)
    }
    fn code(&self) -> &'static str {
        match self.st {
            DirSt::Reading => "R",
            DirSt::Closed => "C",
            DirSt::Writing { .. } => "W",
        }
    }
    /// The forwarded bytes held in userspace, hex, for `--carry-held`.
    fn held_hex(&self) -> String {
        match self.st {
            DirSt::Writing { filled, written } => self.buf[written..filled]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            _ => "-".to_string(),
        }
    }
}

struct Conn {
    id: u64,
    peer: String,
    hops: u32,
    client: TcpStream,
    backend: TcpStream,
    up: Dir,
    down: Dir,
    start_ns: u64,
    last_ns: u64,
    deadline_ns: u64,
}

struct Parked {
    line: String,
    client: OwnedFd,
    backend: OwnedFd,
}

struct ConnCtl {
    mode: AtomicU8,
    phase: AtomicU8,
}

struct Session {
    client: SocketAddr,
    upstream: UdpSocket,
    park: Notify,
    req: AtomicU64,
    resp: AtomicU64,
    start_ns: u64,
    last_ns: AtomicU64,
    hops: u32,
}

struct SessionEntry {
    sess: Arc<Session>,
    task: JoinHandle<bool>,
}

struct Shared {
    opts: Opts,
    log: Mutex<std::fs::File>,
    conns: Mutex<HashMap<u64, Arc<ConnCtl>>>,
    next_id: AtomicU64,
    epoch: watch::Sender<u64>,
    parked_tx: mpsc::UnboundedSender<(u64, Parked)>,
    parked_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<(u64, Parked)>>,
    slot: Mutex<Option<Arc<UdpSocket>>>,
    sessions: Mutex<HashMap<SocketAddr, SessionEntry>>,
}

impl Shared {
    fn log(&self, line: &str) {
        let mut f = self.log.lock().unwrap();
        let _ = writeln!(f, "{} {}", mono_ns(), line);
    }
    fn bump_epoch(&self) {
        self.epoch.send_modify(|e| *e += 1);
    }
}

enum Step {
    Data,
    Fin,
}

async fn step(d: &mut Dir, r: &TcpStream, w: &TcpStream, parking: bool) -> io::Result<Step> {
    match d.st {
        DirSt::Closed => std::future::pending().await,
        DirSt::Reading if parking => std::future::pending().await,
        DirSt::Reading => loop {
            r.readable().await?;
            match r.try_read(&mut d.buf) {
                Ok(0) => {
                    shutdown_write(w.as_raw_fd());
                    d.st = DirSt::Closed;
                    return Ok(Step::Fin);
                }
                Ok(n) => {
                    d.st = DirSt::Writing {
                        filled: n,
                        written: 0,
                    };
                    return Ok(Step::Data);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        },
        DirSt::Writing { filled, written } => loop {
            w.writable().await?;
            match w.try_write(&d.buf[written..filled]) {
                Ok(n) => {
                    d.bytes += n as u64;
                    d.st = if written + n == filled {
                        DirSt::Reading
                    } else {
                        DirSt::Writing {
                            filled,
                            written: written + n,
                        }
                    };
                    return Ok(Step::Data);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        },
    }
}

impl Conn {
    fn into_parked(self) -> io::Result<Parked> {
        // `into_std` deregisters from this process's epoll before the fd
        // leaves: an fd still registered here would keep waking this
        // runtime for a socket another process now reads.
        let client: OwnedFd = self.client.into_std()?.into();
        let backend: OwnedFd = self.backend.into_std()?.into();
        let line = format!(
            "TCP id={} peer={} hops={} up={} upb={} down={} downb={} start={} last={} dl={} inq_c={} inq_b={} outq_c={} outq_b={} uph={} downh={}",
            self.id,
            self.peer,
            self.hops,
            self.up.code(),
            self.up.bytes,
            self.down.code(),
            self.down.bytes,
            self.start_ns,
            self.last_ns,
            self.deadline_ns,
            inq(client.as_raw_fd()),
            inq(backend.as_raw_fd()),
            outq(client.as_raw_fd()),
            outq(backend.as_raw_fd()),
            self.up.held_hex(),
            self.down.held_hex(),
        );
        Ok(Parked {
            line,
            client,
            backend,
        })
    }
}

fn spawn_conn(sh: &Arc<Shared>, ctl: Arc<ConnCtl>, c: Conn) {
    let sh2 = sh.clone();
    let epoch = sh.epoch.subscribe();
    tokio::spawn(conn_task(sh2, ctl, c, epoch));
}

async fn conn_task(
    sh: Arc<Shared>,
    ctl: Arc<ConnCtl>,
    mut c: Conn,
    mut epoch: watch::Receiver<u64>,
) {
    let idle_ns = sh.opts.idle_timeout_ms * 1_000_000;
    let reason: &str = loop {
        let parking = ctl.mode.load(SeqCst) == PARK_REQ;
        let quiesced = sh.opts.carry_held || (c.up.at_rest() && c.down.at_rest());
        if parking && quiesced {
            if ctl
                .mode
                .compare_exchange(PARK_REQ, PARKED, SeqCst, SeqCst)
                .is_ok()
            {
                let id = c.id;
                match c.into_parked() {
                    Ok(p) => {
                        let _ = sh.parked_tx.send((id, p));
                    }
                    Err(e) => sh.log(&format!("PARK_FAIL id={id} err={e}")),
                }
                return;
            }
            continue;
        }
        if c.up.st == DirSt::Closed && c.down.st == DirSt::Closed {
            break "fin";
        }
        let now = mono_ns();
        let idle_dl = c.last_ns + idle_ns;
        let dl = if c.deadline_ns > 0 {
            idle_dl.min(c.deadline_ns)
        } else {
            idle_dl
        };
        if now >= dl {
            break if c.deadline_ns > 0 && now >= c.deadline_ns {
                "total_timeout"
            } else {
                "idle_timeout"
            };
        }
        let sleep = tokio::time::sleep(Duration::from_nanos(dl - now));
        let Conn {
            client,
            backend,
            up,
            down,
            ..
        } = &mut c;
        let res = tokio::select! {
            _ = epoch.changed() => continue,
            _ = sleep => continue,
            r = step(up, client, backend, parking) => r,
            r = step(down, backend, client, parking) => r,
        };
        match res {
            Ok(Step::Data) | Ok(Step::Fin) => c.last_ns = mono_ns(),
            Err(_) => break "reset",
        }
    };
    ctl.mode.store(ENDED, SeqCst);
    sh.conns.lock().unwrap().remove(&c.id);
    let dur_ms = (mono_ns() - c.start_ns) / 1_000_000;
    sh.log(&format!(
        "END id={} gen={} peer={} reason={} up={} down={} dur_ms={} hops={}",
        c.id, sh.opts.gen, c.peer, reason, c.up.bytes, c.down.bytes, dur_ms, c.hops
    ));
}

async fn new_conn(sh: Arc<Shared>, client: TcpStream, peer: SocketAddr) {
    let id = (u64::from(sh.opts.gen) << 40)
        | (u64::from(sh.opts.attempt) << 32)
        | sh.next_id.fetch_add(1, SeqCst);
    let ctl = Arc::new(ConnCtl {
        mode: AtomicU8::new(RUN),
        phase: AtomicU8::new(CONNECTING),
    });
    sh.conns.lock().unwrap().insert(id, ctl.clone());
    let start = mono_ns();
    let backend = match TcpStream::connect(sh.opts.backend_tcp).await {
        Ok(b) => b,
        Err(e) => {
            sh.conns.lock().unwrap().remove(&id);
            sh.log(&format!(
                "END id={id} gen={} peer={peer} reason=connect_failed err={e}",
                sh.opts.gen
            ));
            return;
        }
    };
    ctl.phase.store(FORWARDING, SeqCst);
    let deadline_ns = if sh.opts.total_timeout_ms > 0 {
        start + sh.opts.total_timeout_ms * 1_000_000
    } else {
        0
    };
    let c = Conn {
        id,
        peer: peer.to_string(),
        hops: 0,
        client,
        backend,
        up: Dir::new(DirSt::Reading, 0),
        down: Dir::new(DirSt::Reading, 0),
        start_ns: start,
        last_ns: start,
        deadline_ns,
    };
    let epoch = sh.epoch.subscribe();
    conn_task(sh, ctl, c, epoch).await;
}

async fn accept_task(
    sh: Arc<Shared>,
    listener: TcpListener,
    mut stop: watch::Receiver<bool>,
) -> TcpListener {
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => return listener,
            r = listener.accept() => {
                if let Ok((s, peer)) = r {
                    tokio::spawn(new_conn(sh.clone(), s, peer));
                }
            }
        }
    }
}

/// A datagram sent with the syscall, not tokio's `try_send`: tokio
/// answers `WouldBlock` until its reactor has seen the socket writable
/// once, and a socket registered a moment ago (fresh, or just adopted
/// from the other generation) has not. Lorica's `session.rs` already
/// sends with `sendmsg` on the raw fd.
fn raw_send(fd: RawFd, data: &[u8]) -> bool {
    // SAFETY: `data` is valid for its length; the fd is open.
    unsafe { libc::send(fd, data.as_ptr().cast(), data.len(), libc::MSG_DONTWAIT) >= 0 }
}

fn raw_send_to(fd: RawFd, data: &[u8], to: SocketAddr) -> bool {
    let SocketAddr::V4(v4) = to else { return false };
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: v4.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(v4.ip().octets()),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: `sin` and `data` outlive the call; sizes are passed.
    unsafe {
        libc::sendto(
            fd,
            data.as_ptr().cast(),
            data.len(),
            libc::MSG_DONTWAIT,
            (&sin as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) >= 0
    }
}

fn spawn_session(sh: &Arc<Shared>, sess: Arc<Session>) {
    let sh2 = sh.clone();
    let s2 = sess.clone();
    let task = tokio::spawn(session_task(sh2, s2));
    sh.sessions
        .lock()
        .unwrap()
        .insert(sess.client, SessionEntry { sess, task });
}

/// Returns true when it parked, false when it ended.
async fn session_task(sh: Arc<Shared>, s: Arc<Session>) -> bool {
    let mut buf = vec![0u8; 65536];
    let idle_ns = sh.opts.udp_idle_ms * 1_000_000;
    loop {
        let last = s.last_ns.load(SeqCst);
        let now = mono_ns();
        if now >= last + idle_ns {
            break;
        }
        tokio::select! {
            biased;
            _ = s.park.notified() => return true,
            _ = tokio::time::sleep(Duration::from_nanos(last + idle_ns - now)) => continue,
            r = s.upstream.recv(&mut buf) => {
                let Ok(n) = r else { continue };
                let slot = sh.slot.lock().unwrap().clone();
                if let Some(slot) = slot {
                    if raw_send_to(slot.as_raw_fd(), &buf[..n], s.client) {
                        s.resp.fetch_add(1, SeqCst);
                    } else {
                        sh.log(&format!("UDROP dir=resp client={}", s.client));
                    }
                }
                s.last_ns.store(mono_ns(), SeqCst);
            }
        }
    }
    sh.sessions.lock().unwrap().remove(&s.client);
    sh.log(&format!(
        "UEND client={} gen={} req={} resp={} hops={} port={}",
        s.client,
        sh.opts.gen,
        s.req.load(SeqCst),
        s.resp.load(SeqCst),
        s.hops,
        s.upstream.local_addr().map(|a| a.port()).unwrap_or(0)
    ));
    false
}

async fn udp_recv_task(sh: Arc<Shared>, slot: Arc<UdpSocket>, mut stop: watch::Receiver<bool>) {
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, from) = tokio::select! {
            biased;
            _ = stop.changed() => return,
            r = slot.recv_from(&mut buf) => match r { Ok(v) => v, Err(_) => continue },
        };
        // From here to the send, nothing awaits on an existing session:
        // a datagram read is forwarded before the next stop check.
        let existing = sh
            .sessions
            .lock()
            .unwrap()
            .get(&from)
            .map(|e| e.sess.clone());
        let sess = match existing {
            Some(s) => s,
            None => {
                let Ok(up) = UdpSocket::bind("127.0.0.1:0").await else {
                    continue;
                };
                if up.connect(sh.opts.backend_udp).await.is_err() {
                    continue;
                }
                let now = mono_ns();
                let s = Arc::new(Session {
                    client: from,
                    upstream: up,
                    park: Notify::new(),
                    req: AtomicU64::new(0),
                    resp: AtomicU64::new(0),
                    start_ns: now,
                    last_ns: AtomicU64::new(now),
                    hops: 0,
                });
                sh.log(&format!(
                    "UOPEN client={from} gen={} port={}",
                    sh.opts.gen,
                    s.upstream.local_addr().map(|a| a.port()).unwrap_or(0)
                ));
                spawn_session(&sh, s.clone());
                s
            }
        };
        if raw_send(sess.upstream.as_raw_fd(), &buf[..n]) {
            sess.req.fetch_add(1, SeqCst);
        } else {
            sh.log(&format!("UDROP dir=req client={from}"));
        }
        sess.last_ns.store(mono_ns(), SeqCst);
    }
}

/// What a generation runs.
struct Plane {
    listener: Option<TcpListener>,
    accept_stop: Option<watch::Sender<bool>>,
    accept: Option<JoinHandle<TcpListener>>,
    udp_stop: Option<watch::Sender<bool>>,
    udp: Option<JoinHandle<()>>,
}

impl Plane {
    fn start(&mut self, sh: &Arc<Shared>) {
        let listener = self.listener.take().expect("listener held");
        let (tx, rx) = watch::channel(false);
        self.accept = Some(tokio::spawn(accept_task(sh.clone(), listener, rx)));
        self.accept_stop = Some(tx);
        self.start_udp(sh);
    }
    fn start_udp(&mut self, sh: &Arc<Shared>) {
        let slot = sh.slot.lock().unwrap().clone().expect("slot held");
        let (tx, rx) = watch::channel(false);
        self.udp = Some(tokio::spawn(udp_recv_task(sh.clone(), slot, rx)));
        self.udp_stop = Some(tx);
    }
    async fn stop_accept(&mut self) {
        if let Some(tx) = self.accept_stop.take() {
            let _ = tx.send(true);
        }
        if let Some(h) = self.accept.take() {
            self.listener = Some(h.await.expect("accept task"));
        }
    }
    async fn stop_udp(&mut self) {
        if let Some(tx) = self.udp_stop.take() {
            let _ = tx.send(true);
        }
        if let Some(h) = self.udp.take() {
            let _ = h.await;
        }
    }
}

struct ParkedSession {
    line: String,
    upstream: OwnedFd,
}

fn spawn_child(opts: &Opts, gen: u32, attempt: u32) -> io::Result<(Child, Chan)> {
    let (ours, theirs) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(io::Error::from)?;
    let raw = theirs.as_raw_fd();
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.arg("proxy").args(opts.child_args(gen, attempt));
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if raw != 3 && libc::dup2(raw, 3) < 0 {
                return Err(io::Error::last_os_error());
            }
            libc::fcntl(3, libc::F_SETFD, 0);
            Ok(())
        });
    }
    let child = cmd.spawn()?;
    drop(theirs);
    Ok((child, Chan::new(ours)))
}

enum Outcome {
    Committed,
    Aborted(&'static str),
    /// `COMMITTED` was sent but the new generation was killed: the
    /// connections were its, and are lost.
    LostAfterCommit,
}

/// The blocking half of the old generation's handover.
fn old_protocol(
    opts: &Opts,
    chan: &Chan,
    child: &mut Child,
    tcp: &[Parked],
    udp: &[ParkedSession],
    attempt: u32,
    times: &mut [u64; 3],
) -> Outcome {
    times[0] = mono_ns();
    for p in tcp {
        if chan
            .send(&p.line, &[p.client.as_raw_fd(), p.backend.as_raw_fd()])
            .is_err()
        {
            return Outcome::Aborted("send_failed");
        }
    }
    for s in udp {
        if chan.send(&s.line, &[s.upstream.as_raw_fd()]).is_err() {
            return Outcome::Aborted("send_failed");
        }
    }
    if chan
        .send(&format!("END tcp={} udp={}", tcp.len(), udp.len()), &[])
        .is_err()
    {
        return Outcome::Aborted("send_failed");
    }
    match chan.recv(opts.ready_timeout_ms) {
        Ok(Recv::Msg(m, _)) if m == "READY" => {}
        Ok(Recv::TimedOut) => return Outcome::Aborted("ready_timeout"),
        _ => return Outcome::Aborted("no_ready"),
    }
    times[1] = mono_ns();
    let old_fault = opts.crash_for_old(opts.gen, attempt);
    if old_fault == Some("old-crash-after-ready") {
        std::process::exit(3);
    }
    if old_fault == Some("old-abort-after-ready") {
        let _ = chan.send("ABORT", &[]);
        return Outcome::Aborted("old_decided_abort");
    }
    if chan.send("COMMIT", &[]).is_err() {
        return Outcome::Aborted("commit_send_failed");
    }
    match chan.recv(opts.commit_timeout_ms) {
        Ok(Recv::Msg(m, _)) if m == "COMMITTED" => {
            times[2] = mono_ns();
            Outcome::Committed
        }
        Ok(Recv::TimedOut) => {
            let _ = child.kill();
            let _ = child.wait();
            if chan.drain_queued().iter().any(|m| m == "COMMITTED") {
                Outcome::LostAfterCommit
            } else {
                Outcome::Aborted("commit_timeout_killed")
            }
        }
        _ => Outcome::Aborted("eof_before_committed"),
    }
}

impl Opts {
    /// Faults injected in the old generation itself, keyed by its own
    /// generation number (`old-...` points in the schedule).
    fn crash_for_old(&self, gen: u32, attempt: u32) -> Option<&str> {
        if attempt != 0 {
            return None;
        }
        self.crash_schedule.split(',').find_map(|e| {
            let (g, point) = e.split_once(':')?;
            (g.parse::<u32>().ok()? == gen && point.starts_with("old-")).then_some(point)
        })
    }
}

/// One handover attempt from the old side. Returns true when committed.
async fn handover(sh: &Arc<Shared>, plane: &mut Plane, attempt: u32) -> bool {
    let opts = &sh.opts;
    let next = opts.gen + 1;
    let (mut child, chan) = match spawn_child(opts, next, attempt) {
        Ok(v) => v,
        Err(e) => {
            sh.log(&format!(
                "HANDOVER gen={} attempt={attempt} outcome=spawn_failed err={e}",
                opts.gen
            ));
            return false;
        }
    };
    let chan = Arc::new(chan);
    let c2 = chan.clone();
    let hello = tokio::task::spawn_blocking(move || c2.recv(5000))
        .await
        .unwrap();
    if !matches!(hello, Ok(Recv::Msg(ref m, _)) if m == "HELLO") {
        let _ = child.kill();
        let _ = tokio::task::spawn_blocking(move || child.wait()).await;
        sh.log(&format!(
            "HANDOVER gen={} attempt={attempt} outcome=aborted reason=no_hello",
            opts.gen
        ));
        return false;
    }

    // Stop taking new work, keep the listeners.
    let park_req_ns = mono_ns();
    plane.stop_accept().await;
    if !opts.udp_naive {
        plane.stop_udp().await;
    }
    let listener = plane.listener.take().expect("listener back");
    let listener_fd: OwnedFd = listener.into_std().expect("listener into_std").into();
    let slot_fd = sh.slot.lock().unwrap().as_ref().unwrap().as_raw_fd();
    {
        let c2 = chan.clone();
        let lfd = listener_fd.as_raw_fd();
        let _ = tokio::task::spawn_blocking(move || c2.send("LISTENERS", &[lfd, slot_fd]))
            .await
            .unwrap();
    }

    // Park.
    let mut requested: Vec<(u64, Arc<ConnCtl>)> = Vec::new();
    let mut ineligible = 0u32;
    for (id, ctl) in sh.conns.lock().unwrap().iter() {
        if ctl.phase.load(SeqCst) == FORWARDING && ctl.mode.load(SeqCst) != ENDED {
            ctl.mode.store(PARK_REQ, SeqCst);
            requested.push((*id, ctl.clone()));
        } else {
            ctl.mode.store(DRAIN, SeqCst);
            ineligible += 1;
        }
    }
    sh.bump_epoch();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(opts.transfer_timeout_ms);
    let mut parked: HashMap<u64, Parked> = HashMap::new();
    let mut rx = sh.parked_rx.lock().await;
    let mut pending: usize = requested.len();
    while pending > 0 {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some((id, p))) => {
                parked.insert(id, p);
                pending -= 1;
            }
            _ => break,
        }
    }
    let mut not_quiesced = Vec::new();
    for (id, ctl) in &requested {
        if parked.contains_key(id) {
            continue;
        }
        match ctl.mode.compare_exchange(PARK_REQ, DRAIN, SeqCst, SeqCst) {
            Ok(_) => not_quiesced.push(*id),
            Err(PARKED) => {
                // It won the race: its message is on the way.
                if let Some((pid, p)) = rx.recv().await {
                    parked.insert(pid, p);
                }
            }
            Err(_) => {}
        }
    }
    drop(rx);
    sh.bump_epoch();
    for id in &not_quiesced {
        sh.log(&format!(
            "FALLBACK id={id} gen={} reason=not_quiesced",
            opts.gen
        ));
    }
    // Remove the parked ones from the registry: their task has returned.
    {
        let mut conns = sh.conns.lock().unwrap();
        for id in parked.keys() {
            conns.remove(id);
        }
    }

    // Park UDP sessions: stop their tasks, take their sockets.
    let entries: Vec<(SocketAddr, SessionEntry)> = sh.sessions.lock().unwrap().drain().collect();
    let mut sessions: Vec<ParkedSession> = Vec::new();
    for (addr, e) in entries {
        e.sess.park.notify_one();
        let parked_ok = e.task.await.unwrap_or(false);
        if !parked_ok {
            continue;
        }
        let mut sess = e.sess;
        let s = loop {
            match Arc::try_unwrap(sess) {
                Ok(s) => break s,
                Err(back) => {
                    sess = back;
                    tokio::task::yield_now().await;
                }
            }
        };
        let fd: OwnedFd = s.upstream.into_std().expect("udp into_std").into();
        sessions.push(ParkedSession {
            line: format!(
                "UDP client={addr} req={} resp={} start={} last={} hops={} inq={}",
                s.req.load(SeqCst),
                s.resp.load(SeqCst),
                s.start_ns,
                s.last_ns.load(SeqCst),
                s.hops,
                inq(fd.as_raw_fd()),
            ),
            upstream: fd,
        });
    }
    let park_done_ns = mono_ns();

    let tcp: Vec<Parked> = parked.into_values().collect();
    let inq_total: i64 = tcp
        .iter()
        .map(|p| inq(p.client.as_raw_fd()) + inq(p.backend.as_raw_fd()))
        .sum();
    let held: Vec<u64> = tcp
        .iter()
        .map(|p| {
            ["uph", "downh"]
                .iter()
                .map(|k| {
                    field(&p.line, k)
                        .filter(|v| *v != "-")
                        .map_or(0, |v| v.len() as u64 / 2)
                })
                .sum()
        })
        .collect();
    let held_conns = held.iter().filter(|h| **h > 0).count();
    let held_bytes: u64 = held.iter().sum();
    let outq_total: i64 = tcp
        .iter()
        .map(|p| outq(p.client.as_raw_fd()) + outq(p.backend.as_raw_fd()))
        .sum();

    let opts2 = opts.clone();
    let c2 = chan.clone();
    let (outcome, tcp, sessions, mut child, times) = tokio::task::spawn_blocking(move || {
        let mut times = [0u64; 3];
        let o = old_protocol(
            &opts2, &c2, &mut child, &tcp, &sessions, attempt, &mut times,
        );
        (o, tcp, sessions, child, times)
    })
    .await
    .unwrap();

    let summary = format!(
        "gen={} attempt={attempt} park_req={park_req_ns} park_done={park_done_ns} prepare={} ready={} committed={} tcp={} udp={} fallback={} ineligible={ineligible} inq={inq_total} outq={outq_total} held_conns={held_conns} held_bytes={held_bytes}",
        opts.gen,
        times[0],
        times[1],
        times[2],
        tcp.len(),
        sessions.len(),
        not_quiesced.len(),
    );
    match outcome {
        Outcome::Committed => {
            for p in &tcp {
                sh.log(&format!(
                    "TRANSFER {} to_gen={next}",
                    held_as_len(p.line.trim_start_matches("TCP "))
                ));
            }
            for s in &sessions {
                sh.log(&format!(
                    "UTRANSFER {} to_gen={next}",
                    s.line.trim_start_matches("UDP ")
                ));
            }
            sh.log(&format!("HANDOVER {summary} outcome=committed"));
            drop(tcp);
            drop(sessions);
            drop(listener_fd);
            if opts.udp_naive {
                plane.stop_udp().await;
            }
            // The child outlives us; it is reparented on our exit.
            std::mem::forget(child);
            true
        }
        Outcome::LostAfterCommit => {
            sh.log(&format!("HANDOVER {summary} outcome=lost_after_commit"));
            std::process::exit(4);
        }
        Outcome::Aborted(why) => {
            if why == "old_decided_abort" {
                // Let the child act on ABORT before it is killed, so the
                // abort-with-shutdown pitfall shows on every connection
                // rather than on those it reached first.
                for _ in 0..100 {
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
            let _ = child.kill();
            let _ = tokio::task::spawn_blocking(move || child.wait()).await;
            sh.log(&format!("HANDOVER {summary} outcome=aborted reason={why}"));
            // Resume: we still hold every socket and the child never
            // forwarded a byte.
            for p in tcp {
                resume_conn(sh, p);
            }
            for s in sessions {
                adopt_session(sh, &s.line, s.upstream, false);
            }
            for id in &not_quiesced {
                if let Some(ctl) = sh.conns.lock().unwrap().get(id) {
                    let _ = ctl.mode.compare_exchange(DRAIN, RUN, SeqCst, SeqCst);
                }
            }
            for ctl in sh.conns.lock().unwrap().values() {
                let _ = ctl.mode.compare_exchange(DRAIN, RUN, SeqCst, SeqCst);
            }
            let std_l = std::net::TcpListener::from(listener_fd);
            plane.listener = Some(TcpListener::from_std(std_l).expect("listener back"));
            if opts.udp_naive {
                plane.stop_udp().await;
            }
            plane.start(sh);
            false
        }
    }
}

/// A `TCP` line with the held bytes replaced by their count.
fn held_as_len(line: &str) -> String {
    line.split(' ')
        .map(|kv| match kv.split_once('=') {
            Some((k @ ("uph" | "downh"), v)) if v != "-" => format!("{k}={}", v.len() / 2),
            Some((k @ ("uph" | "downh"), _)) => format!("{k}=0"),
            _ => kv.to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_dir(code: &str, bytes: u64, held_hex: &str) -> Dir {
    match code {
        "C" => Dir::new(DirSt::Closed, bytes),
        "W" => {
            let mut d = Dir::new(DirSt::Reading, bytes);
            let held: Vec<u8> = (0..held_hex.len() / 2)
                .map(|i| u8::from_str_radix(&held_hex[2 * i..2 * i + 2], 16).unwrap())
                .collect();
            d.buf[..held.len()].copy_from_slice(&held);
            d.st = DirSt::Writing {
                filled: held.len(),
                written: 0,
            };
            d
        }
        _ => Dir::new(DirSt::Reading, bytes),
    }
}

fn conn_from_line(line: &str, client: OwnedFd, backend: OwnedFd, hop: bool) -> io::Result<Conn> {
    let client = std::net::TcpStream::from(client);
    let backend = std::net::TcpStream::from(backend);
    // O_NONBLOCK lives on the open file description, shared with the
    // other generation: setting it here sets it there too.
    client.set_nonblocking(true)?;
    backend.set_nonblocking(true)?;
    Ok(Conn {
        id: field_u64(line, "id"),
        peer: field(line, "peer").unwrap_or("?").to_string(),
        hops: field_u64(line, "hops") as u32 + u32::from(hop),
        client: TcpStream::from_std(client)?,
        backend: TcpStream::from_std(backend)?,
        up: parse_dir(
            field(line, "up").unwrap_or("R"),
            field_u64(line, "upb"),
            field(line, "uph").unwrap_or("-"),
        ),
        down: parse_dir(
            field(line, "down").unwrap_or("R"),
            field_u64(line, "downb"),
            field(line, "downh").unwrap_or("-"),
        ),
        start_ns: field_u64(line, "start"),
        last_ns: field_u64(line, "last"),
        deadline_ns: field_u64(line, "dl"),
    })
}

fn adopt_conn(sh: &Arc<Shared>, line: &str, client: OwnedFd, backend: OwnedFd, hop: bool) {
    match conn_from_line(line, client, backend, hop) {
        Ok(c) => {
            let ctl = Arc::new(ConnCtl {
                mode: AtomicU8::new(RUN),
                phase: AtomicU8::new(FORWARDING),
            });
            sh.conns.lock().unwrap().insert(c.id, ctl.clone());
            spawn_conn(sh, ctl, c);
        }
        Err(e) => sh.log(&format!("ADOPT_FAIL line={line} err={e}")),
    }
}

fn resume_conn(sh: &Arc<Shared>, p: Parked) {
    adopt_conn(sh, &p.line, p.client, p.backend, false);
}

fn adopt_session(sh: &Arc<Shared>, line: &str, fd: OwnedFd, hop: bool) {
    let std_s = std::net::UdpSocket::from(fd);
    let _ = std_s.set_nonblocking(true);
    let Ok(up) = UdpSocket::from_std(std_s) else {
        return;
    };
    let client: SocketAddr = field(line, "client")
        .and_then(|c| c.parse().ok())
        .expect("client");
    let s = Arc::new(Session {
        client,
        upstream: up,
        park: Notify::new(),
        req: AtomicU64::new(field_u64(line, "req")),
        resp: AtomicU64::new(field_u64(line, "resp")),
        start_ns: field_u64(line, "start"),
        last_ns: AtomicU64::new(field_u64(line, "last")),
        hops: field_u64(line, "hops") as u32 + u32::from(hop),
    });
    spawn_session(sh, s);
}

/// What the new generation receives before it may forward.
struct Received {
    listener: OwnedFd,
    slot: OwnedFd,
    tcp: Vec<(String, OwnedFd, OwnedFd)>,
    udp: Vec<(String, OwnedFd)>,
    presumed: bool,
}

fn crash_point(opts: &Opts, point: &str) {
    let m = parse_args(&opts.raw);
    if m.get("crash-at").map(String::as_str) == Some(point) {
        std::process::exit(9);
    }
    if m.get("crash-at").map(String::as_str) == Some(&format!("hang-{point}")) {
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }
}

/// The new generation's side, blocking, before any runtime exists.
fn new_protocol(opts: &Opts, chan: &Chan, log: &mut std::fs::File) -> Option<Received> {
    crash_point(opts, "before-hello");
    chan.send("HELLO", &[]).ok()?;
    let (listener, slot) = match chan.recv(-1) {
        Ok(Recv::Msg(m, mut fds)) if m == "LISTENERS" && fds.len() == 2 => {
            let slot = fds.pop().unwrap();
            (fds.pop().unwrap(), slot)
        }
        _ => return None,
    };
    let mut tcp = Vec::new();
    let mut udp = Vec::new();
    loop {
        match chan.recv(-1) {
            Ok(Recv::Msg(m, mut fds)) if m.starts_with("TCP ") && fds.len() == 2 => {
                let b = fds.pop().unwrap();
                let c = fds.pop().unwrap();
                tcp.push((m, c, b));
            }
            Ok(Recv::Msg(m, mut fds)) if m.starts_with("UDP ") && fds.len() == 1 => {
                udp.push((m, fds.pop().unwrap()));
            }
            Ok(Recv::Msg(m, _)) if m.starts_with("END ") => {
                if field_u64(&m, "tcp") as usize != tcp.len()
                    || field_u64(&m, "udp") as usize != udp.len()
                {
                    return None;
                }
                break;
            }
            _ => return None,
        }
    }
    crash_point(opts, "before-ready");
    chan.send("READY", &[]).ok()?;
    crash_point(opts, "after-ready");
    let presumed = match chan.recv(-1) {
        Ok(Recv::Msg(m, _)) if m == "COMMIT" => false,
        Ok(Recv::Msg(m, _)) if m == "ABORT" => {
            if opts.abort_with_shutdown {
                // The pitfall on purpose: a shutdown acts on the socket,
                // which the old generation is about to resume.
                for (_, c, b) in &tcp {
                    shutdown_both(c.as_raw_fd());
                    shutdown_both(b.as_raw_fd());
                }
            }
            let _ = writeln!(
                log,
                "{} ABORTED gen={} attempt={} tcp={} with_shutdown={}",
                mono_ns(),
                opts.gen,
                opts.attempt,
                tcp.len(),
                opts.abort_with_shutdown
            );
            return None;
        }
        // The old generation died after READY without deciding. It sends
        // ABORT before it ever resumes, so a bare EOF means nobody else
        // forwards these sockets.
        Ok(Recv::Eof) => true,
        _ => return None,
    };
    crash_point(opts, "before-committed");
    if !presumed {
        chan.send("COMMITTED", &[]).ok()?;
    }
    Some(Received {
        listener,
        slot,
        tcp,
        udp,
        presumed,
    })
}

pub fn main(args: &[String]) {
    let opts = Opts::parse(args);
    std::fs::create_dir_all(&opts.dir).ok();
    let log_path = opts
        .dir
        .join(format!("log-g{}-a{}.txt", opts.gen, opts.attempt));
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .expect("log");

    let received = match opts.handover_fd {
        // SAFETY: fd 3 was set up for us by our parent's `pre_exec`.
        Some(fd) => {
            let chan = Chan::new(unsafe { OwnedFd::from_raw_fd(fd) });
            match new_protocol(&opts, &chan, &mut log) {
                Some(r) => Some((r, chan)),
                None => std::process::exit(0),
            }
        }
        None => None,
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(serve(opts, log, received));
}

async fn serve(opts: Opts, log: std::fs::File, received: Option<(Received, Chan)>) {
    let (parked_tx, parked_rx) = mpsc::unbounded_channel();
    let (epoch, _) = watch::channel(0u64);
    let sh = Arc::new(Shared {
        opts: opts.clone(),
        log: Mutex::new(log),
        conns: Mutex::new(HashMap::new()),
        next_id: AtomicU64::new(1),
        epoch,
        parked_tx,
        parked_rx: tokio::sync::Mutex::new(parked_rx),
        slot: Mutex::new(None),
        sessions: Mutex::new(HashMap::new()),
    });

    let mut plane = Plane {
        listener: None,
        accept_stop: None,
        accept: None,
        udp_stop: None,
        udp: None,
    };
    let mut _chan_keepalive = None;
    match received {
        None => {
            let l = std::net::TcpListener::bind(opts.listen).expect("bind tcp");
            // std listens with a backlog of 128; the scale scenario opens
            // a thousand connections at once.
            // SAFETY: plain syscall on a listening socket we own.
            unsafe { libc::listen(l.as_raw_fd(), 4096) };
            l.set_nonblocking(true).unwrap();
            plane.listener = Some(TcpListener::from_std(l).unwrap());
            let u = std::net::UdpSocket::bind(opts.listen).expect("bind udp");
            u.set_nonblocking(true).unwrap();
            *sh.slot.lock().unwrap() = Some(Arc::new(UdpSocket::from_std(u).unwrap()));
        }
        Some((r, chan)) => {
            let l = std::net::TcpListener::from(r.listener);
            l.set_nonblocking(true).unwrap();
            plane.listener = Some(TcpListener::from_std(l).unwrap());
            let u = std::net::UdpSocket::from(r.slot);
            u.set_nonblocking(true).unwrap();
            *sh.slot.lock().unwrap() = Some(Arc::new(UdpSocket::from_std(u).unwrap()));
            let n_tcp = r.tcp.len();
            let n_udp = r.udp.len();
            for (line, c, b) in r.tcp {
                adopt_conn(&sh, &line, c, b, true);
            }
            for (line, fd) in r.udp {
                adopt_session(&sh, &line, fd, true);
            }
            sh.log(&format!(
                "ADOPT gen={} attempt={} tcp={n_tcp} udp={n_udp} presumed={}",
                opts.gen, opts.attempt, r.presumed
            ));
            _chan_keepalive = Some(chan);
        }
    }
    plane.start(&sh);
    std::fs::write(opts.dir.join("current.gen"), opts.gen.to_string()).ok();

    if opts.gen < opts.upgrades {
        tokio::time::sleep(Duration::from_millis(opts.interval_ms)).await;
        let mut attempt = 0;
        loop {
            if handover(&sh, &mut plane, attempt).await {
                break;
            }
            attempt += 1;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // Drain what did not transfer, then go.
        let deadline = mono_ns() + opts.drain_ms * 1_000_000;
        loop {
            let open = sh.conns.lock().unwrap().len() + sh.sessions.lock().unwrap().len();
            if open == 0 || mono_ns() > deadline {
                sh.log(&format!("EXIT gen={} left={open}", opts.gen));
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        std::fs::write(opts.dir.join(format!("exited-g{}", opts.gen)), "").ok();
        std::process::exit(0);
    }

    // The last generation serves until told to stop, then until empty.
    let stop = opts.dir.join("stop");
    while !stop.exists() {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    plane.stop_accept().await;
    plane.stop_udp().await;
    let deadline = mono_ns() + 20_000 * 1_000_000;
    loop {
        let open = sh.conns.lock().unwrap().len();
        if open == 0 || mono_ns() > deadline {
            sh.log(&format!("EXIT gen={} left={open} final=1", opts.gen));
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    std::fs::write(opts.dir.join("final.done"), "").ok();
    std::process::exit(0);
}
