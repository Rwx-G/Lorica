// Copyright 2026 Romain G. (Lorica)
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

use nix::sys::signal::{self, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{execv, fork, ForkResult, Pid};
use tracing::{info, warn};

use crate::fd_passing;
use crate::WorkerError;

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
struct WorkerHandle {
    id: u32,
    pid: Pid,
    /// Supervisor end of the socketpair (kept alive for potential future commands).
    _cmd_fd: OwnedFd,
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
            self.spawn_worker(id as u32)?;
        }

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
    fn spawn_worker(&mut self, id: u32) -> Result<(), WorkerError> {
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
                    _cmd_fd: supervisor_fd,
                });

                Ok(())
            }
            ForkResult::Child => {
                // Child: close supervisor end, prepare for exec
                drop(supervisor_fd);

                // Clear CLOEXEC on the worker socketpair FD so it survives exec
                let cmd_fd_raw = worker_fd.into_raw_fd();
                fd_passing::clear_cloexec(cmd_fd_raw)?;

                // Build exec arguments: lorica worker --id N --cmd-fd F --data-dir D --log-level L
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

                // execv never returns on success
                unreachable!()
            }
        }
    }

    /// Non-blocking check for worker process status changes.
    ///
    /// Returns a list of events for workers that have exited or crashed.
    /// Does not remove workers from the internal list - call [`restart_worker`] for that.
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
                    // Process already reaped
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

    /// Restart a worker by removing the old handle and spawning a new process.
    pub fn restart_worker(&mut self, id: u32) -> Result<(), WorkerError> {
        self.workers.retain(|w| w.id != id);
        info!(worker_id = id, "restarting worker");
        self.spawn_worker(id)
    }

    /// Send SIGTERM to all workers for graceful shutdown.
    pub fn shutdown_all(&self) {
        for handle in &self.workers {
            if let Err(e) = signal::kill(handle.pid, Signal::SIGTERM) {
                warn!(
                    worker_id = handle.id,
                    pid = handle.pid.as_raw(),
                    error = %e,
                    "failed to send SIGTERM to worker"
                );
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
}

impl Drop for WorkerManager {
    fn drop(&mut self) {
        // Clean up listening socket FDs owned by the supervisor
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
        };
        let mgr = WorkerManager::new(config);
        let events = mgr.check_workers();
        assert!(events.is_empty());
    }
}
