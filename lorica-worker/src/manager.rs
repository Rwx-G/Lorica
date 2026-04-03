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

//! Worker process manager: fork+exec, FD passing, monitoring, auto-restart.
//!
//! The `WorkerManager` runs in the supervisor process. It:
//! 1. Creates TCP listening sockets
//! 2. Forks worker processes via `fork()+execv()`
//! 3. Sends listening FDs to each worker via SCM_RIGHTS
//! 4. Monitors workers and restarts any that crash

use std::ffi::CString;
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use nix::sys::signal::{self, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{execv, fork, ForkResult, Pid};
use tracing::{info, warn};

use crate::fd_passing;
use crate::WorkerError;

/// Maximum backoff delay between restarts.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// If a worker runs longer than this, its restart counter resets.
const STABLE_THRESHOLD: Duration = Duration::from_secs(60);

/// Configuration for the worker pool.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Number of worker processes (default: number of CPU cores).
    pub worker_count: usize,
    /// Path to the data directory (passed to worker via CLI).
    pub data_dir: String,
    /// Log level string (passed to worker via CLI).
    pub log_level: String,
    /// HTTP proxy listen address (e.g. "0.0.0.0:8080").
    pub http_addr: String,
    /// HTTPS proxy listen address (e.g. "0.0.0.0:8443").
    pub https_addr: Option<String>,
    /// HTTPS port number for workers to identify TLS listeners.
    pub https_port: u16,
}

impl WorkerConfig {
    /// Default worker count based on available CPU cores.
    pub fn default_worker_count() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    }
}

/// Events reported by worker monitoring.
#[derive(Debug)]
pub enum WorkerEvent {
    /// Worker exited normally with a status code.
    Exited { id: u32, pid: Pid, status: i32 },
    /// Worker was killed by a signal (crash).
    Crashed { id: u32, pid: Pid, signal: Signal },
}

/// Handle to a running worker process.
pub struct WorkerHandle {
    id: u32,
    pid: Pid,
    /// Supervisor end of the command channel socketpair.
    /// `None` after the FD has been taken via [`take_cmd_fd`].
    cmd_fd: Option<OwnedFd>,
    /// When this worker was last spawned (for backoff calculation).
    spawned_at: Instant,
    /// Consecutive restart count (resets after stable run).
    restart_count: u32,
}

impl WorkerHandle {
    /// Get the worker ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Get the worker PID.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Take ownership of the command channel FD.
    /// Returns `None` if already taken.
    pub fn take_cmd_fd(&mut self) -> Option<OwnedFd> {
        self.cmd_fd.take()
    }
}

/// Manages a pool of worker processes.
pub struct WorkerManager {
    config: WorkerConfig,
    workers: Vec<WorkerHandle>,
    /// Listening socket FDs owned by the supervisor, sent to workers via SCM_RIGHTS.
    listen_fds: Vec<RawFd>,
    /// Bind addresses corresponding to each listen_fd.
    listen_addrs: Vec<String>,
}

impl WorkerManager {
    /// Create a new WorkerManager with the given configuration.
    pub fn new(config: WorkerConfig) -> Self {
        WorkerManager {
            config,
            workers: Vec::new(),
            listen_fds: Vec::new(),
            listen_addrs: Vec::new(),
        }
    }

    /// Create listening sockets and spawn all worker processes.
    ///
    /// This must be called before any tokio runtime or threads are started,
    /// because `fork()` in a multi-threaded process only preserves the calling thread.
    pub fn start(&mut self) -> Result<(), WorkerError> {
        self.create_listen_sockets()?;

        info!(
            worker_count = self.config.worker_count,
            http_addr = %self.config.http_addr,
            "spawning worker processes"
        );

        for id in 0..self.config.worker_count {
            self.spawn_worker(id as u32, 0)?;
        }

        // Close the supervisor's copies of the listening sockets. With
        // SO_REUSEPORT, the kernel would otherwise distribute connections
        // to the supervisor (which has no proxy service), causing requests
        // to hang. Workers have their own copies via SCM_RIGHTS.
        // For respawn, we recreate sockets via create_listen_sockets().
        for &fd in &self.listen_fds {
            unsafe { fd_passing::close_fd(fd) };
        }
        self.listen_fds.clear();

        Ok(())
    }

    /// Create TCP listening sockets for HTTP (and optionally HTTPS).
    fn create_listen_sockets(&mut self) -> Result<(), WorkerError> {
        let (fd, addr) = fd_passing::create_tcp_listener(&self.config.http_addr)?;
        info!(addr = %addr, fd = fd, "created HTTP listener");
        self.listen_fds.push(fd);
        self.listen_addrs.push(addr);

        if let Some(ref https_addr) = self.config.https_addr {
            let (fd, addr) = fd_passing::create_tcp_listener(https_addr)?;
            info!(addr = %addr, fd = fd, "created HTTPS listener");
            self.listen_fds.push(fd);
            self.listen_addrs.push(addr);
        }

        Ok(())
    }

    /// Fork+exec a single worker process and send it the listening FDs.
    fn spawn_worker(&mut self, id: u32, restart_count: u32) -> Result<(), WorkerError> {
        let (supervisor_fd, worker_fd) = fd_passing::create_socketpair()?;

        match unsafe { fork() }.map_err(WorkerError::Fork)? {
            ForkResult::Parent { child } => {
                // Parent: close worker end, send FDs, record handle
                drop(worker_fd);

                fd_passing::send_listener_fds(
                    supervisor_fd.as_raw_fd(),
                    &self.listen_fds,
                    &self.listen_addrs,
                )?;

                info!(worker_id = id, pid = child.as_raw(), "worker spawned");

                self.workers.push(WorkerHandle {
                    id,
                    pid: child,
                    cmd_fd: Some(supervisor_fd),
                    spawned_at: Instant::now(),
                    restart_count,
                });

                Ok(())
            }
            ForkResult::Child => {
                // Child: close supervisor end, prepare for exec
                drop(supervisor_fd);

                // Clear CLOEXEC on the worker socketpair FD so it survives exec
                let cmd_fd_raw = worker_fd.into_raw_fd();
                fd_passing::clear_cloexec(cmd_fd_raw)?;

                // Build exec arguments
                let exe = std::env::current_exe().map_err(WorkerError::CurrentExe)?;
                let exe_str = exe.to_string_lossy().to_string();

                let args_strings = vec![
                    exe_str.clone(),
                    "worker".to_string(),
                    "--id".to_string(),
                    id.to_string(),
                    "--cmd-fd".to_string(),
                    cmd_fd_raw.to_string(),
                    "--data-dir".to_string(),
                    self.config.data_dir.clone(),
                    "--https-port".to_string(),
                    self.config.https_port.to_string(),
                    "--log-level".to_string(),
                    self.config.log_level.clone(),
                ];

                let c_args: Vec<CString> = args_strings
                    .iter()
                    .map(|s| CString::new(s.as_str()).expect("CString conversion failed"))
                    .collect();
                let c_arg_refs: Vec<&std::ffi::CStr> = c_args.iter().map(AsRef::as_ref).collect();

                let exe_cstr = CString::new(exe_str).expect("CString conversion failed");
                execv(&exe_cstr, &c_arg_refs).map_err(WorkerError::Exec)?;

                unreachable!()
            }
        }
    }

    /// Non-blocking check for worker process status changes.
    pub fn check_workers(&self) -> Vec<WorkerEvent> {
        let mut events = Vec::new();

        for handle in &self.workers {
            match waitpid(handle.pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(pid, status)) => {
                    events.push(WorkerEvent::Exited {
                        id: handle.id,
                        pid,
                        status,
                    });
                }
                Ok(WaitStatus::Signaled(pid, signal, _core_dumped)) => {
                    events.push(WorkerEvent::Crashed {
                        id: handle.id,
                        pid,
                        signal,
                    });
                }
                Ok(WaitStatus::StillAlive) | Ok(_) => {}
                Err(nix::Error::ECHILD) => {
                    events.push(WorkerEvent::Exited {
                        id: handle.id,
                        pid: handle.pid,
                        status: -1,
                    });
                }
                Err(e) => {
                    warn!(
                        worker_id = handle.id,
                        pid = handle.pid.as_raw(),
                        error = %e,
                        "waitpid error"
                    );
                }
            }
        }

        events
    }

    /// Restart a worker with exponential backoff.
    ///
    /// If the worker ran for less than [`STABLE_THRESHOLD`], the restart counter
    /// increments and a delay of `min(2^count, 30)` seconds is applied.
    /// If it ran long enough, the counter resets.
    ///
    /// Returns the new worker's command channel FD (for re-registering in the
    /// supervisor's channel map).
    pub fn restart_worker(&mut self, id: u32) -> Result<Option<OwnedFd>, WorkerError> {
        // Retrieve the old handle's backoff state
        let (prev_restart_count, prev_spawned_at) = self
            .workers
            .iter()
            .find(|w| w.id == id)
            .map(|w| (w.restart_count, w.spawned_at))
            .unwrap_or((0, Instant::now()));

        self.workers.retain(|w| w.id != id);

        // Reset counter if the worker was stable, otherwise increment
        let next_count = if prev_spawned_at.elapsed() >= STABLE_THRESHOLD {
            0
        } else {
            prev_restart_count + 1
        };

        // Apply exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s, 30s, ...
        if next_count > 0 {
            let delay_secs = (1u64 << (next_count - 1).min(5)).min(MAX_BACKOFF.as_secs());
            let delay = Duration::from_secs(delay_secs);
            warn!(
                worker_id = id,
                restart_count = next_count,
                backoff_secs = delay_secs,
                "applying restart backoff"
            );
            std::thread::sleep(delay);
        }

        info!(worker_id = id, restart_count = next_count, "restarting worker");

        // Recreate listening sockets if they were closed after initial spawn
        if self.listen_fds.is_empty() {
            self.create_listen_sockets()?;
        }
        self.spawn_worker(id, next_count)?;

        // Close supervisor's copies again so kernel doesn't route to us
        for &fd in &self.listen_fds {
            unsafe { fd_passing::close_fd(fd) };
        }
        self.listen_fds.clear();

        // Return the cmd_fd of the newly spawned worker
        let fd = self
            .workers
            .iter_mut()
            .find(|w| w.id == id)
            .and_then(|w| w.take_cmd_fd());
        Ok(fd)
    }

    /// Send SIGTERM to all workers for graceful shutdown.
    /// Graceful shutdown: send SIGTERM so workers stop accepting new connections
    /// and drain active ones. After the drain timeout, send SIGKILL to any
    /// workers still alive. Follows the Sozu soft-stop pattern.
    pub fn shutdown_all(&self) {
        self.shutdown_all_with_timeout(Duration::from_secs(30));
    }

    fn shutdown_all_with_timeout(&self, drain_timeout: Duration) {
        info!("sending SIGTERM to all workers (drain timeout: {}s)", drain_timeout.as_secs());
        for handle in &self.workers {
            let _ = signal::kill(handle.pid, Signal::SIGTERM);
            info!(worker_id = handle.id, pid = handle.pid.as_raw(), "sent SIGTERM to worker");
        }

        // Wait for workers to drain active connections and exit
        let deadline = Instant::now() + drain_timeout;
        loop {
            let all_dead = self.workers.iter().all(|h| {
                signal::kill(h.pid, None).is_err()
            });
            if all_dead {
                info!("all workers exited after draining connections");
                return;
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        // Drain timeout exceeded - force kill remaining workers
        warn!("drain timeout exceeded, sending SIGKILL to remaining workers");
        for handle in &self.workers {
            if signal::kill(handle.pid, None).is_ok() {
                let _ = signal::kill(handle.pid, Signal::SIGKILL);
                warn!(worker_id = handle.id, "SIGKILL sent to worker");
            }
        }
    }

    /// Number of currently tracked workers.
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// PIDs of all currently tracked workers.
    pub fn worker_pids(&self) -> Vec<(u32, Pid)> {
        self.workers.iter().map(|w| (w.id, w.pid)).collect()
    }

    /// Take ownership of the worker handles (for passing to async tasks).
    pub fn take_workers(&mut self) -> Vec<WorkerHandle> {
        std::mem::take(&mut self.workers)
    }

    /// Get a reference to the worker handles.
    pub fn workers(&self) -> &[WorkerHandle] {
        &self.workers
    }

    /// Get mutable access to worker handles (e.g. to take cmd_fds).
    pub fn workers_mut(&mut self) -> &mut [WorkerHandle] {
        &mut self.workers
    }
}

impl Drop for WorkerManager {
    fn drop(&mut self) {
        for &fd in &self.listen_fds {
            unsafe { fd_passing::close_fd(fd) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_worker_count() {
        let count = WorkerConfig::default_worker_count();
        assert!(count >= 1);
    }

    #[test]
    fn test_worker_manager_new() {
        let config = WorkerConfig {
            worker_count: 2,
            data_dir: "/tmp".to_string(),
            log_level: "info".to_string(),
            http_addr: "127.0.0.1:0".to_string(),
            https_addr: None,
            https_port: 0,
        };
        let mgr = WorkerManager::new(config);
        assert_eq!(mgr.worker_count(), 0);
        assert!(mgr.listen_fds.is_empty());
    }

    #[test]
    fn test_create_listen_sockets_http_only() {
        let config = WorkerConfig {
            worker_count: 1,
            data_dir: "/tmp".to_string(),
            log_level: "info".to_string(),
            http_addr: "127.0.0.1:0".to_string(),
            https_addr: None,
        };
        let mut mgr = WorkerManager::new(config);
        mgr.create_listen_sockets().expect("create sockets failed");
        assert_eq!(mgr.listen_fds.len(), 1);
        assert_eq!(mgr.listen_addrs.len(), 1);
    }

    #[test]
    fn test_create_listen_sockets_http_and_https() {
        let config = WorkerConfig {
            worker_count: 1,
            data_dir: "/tmp".to_string(),
            log_level: "info".to_string(),
            http_addr: "127.0.0.1:0".to_string(),
            https_addr: Some("127.0.0.1:0".to_string()),
        };
        let mut mgr = WorkerManager::new(config);
        mgr.create_listen_sockets().expect("create sockets failed");
        assert_eq!(mgr.listen_fds.len(), 2);
        assert_eq!(mgr.listen_addrs.len(), 2);
    }

    #[test]
    fn test_check_workers_empty() {
        let config = WorkerConfig {
            worker_count: 0,
            data_dir: "/tmp".to_string(),
            log_level: "info".to_string(),
            http_addr: "127.0.0.1:0".to_string(),
            https_addr: None,
            https_port: 0,
        };
        let mgr = WorkerManager::new(config);
        let events = mgr.check_workers();
        assert!(events.is_empty());
    }

    #[test]
    fn test_backoff_calculation() {
        // Verify that the backoff formula produces correct delays
        // 2^0=1, 2^1=2, 2^2=4, 2^3=8, 2^4=16, 2^5=32->capped to 30
        assert_eq!((1u64 << 0u32.min(5)).min(30), 1);
        assert_eq!((1u64 << 1u32.min(5)).min(30), 2);
        assert_eq!((1u64 << 2u32.min(5)).min(30), 4);
        assert_eq!((1u64 << 3u32.min(5)).min(30), 8);
        assert_eq!((1u64 << 4u32.min(5)).min(30), 16);
        assert_eq!((1u64 << 5u32.min(5)).min(30), 30);
        assert_eq!((1u64 << 6u32.min(5)).min(30), 30);
    }
}
