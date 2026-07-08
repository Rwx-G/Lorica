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

//! Process primitives for the Story 8.4 hot binary-upgrade handoff.
//!
//! The supervisor crate owns the `unsafe` `fork`/`execv` here (it already
//! forks workers) so the `lorica` binary crate can drive the handoff with
//! only safe calls. Three operations are exposed:
//!
//! - [`fork_exec`] launches the staged new binary as a child process and
//!   returns its PID. The old supervisor keeps that PID to watch for an
//!   early exit (rollback signal) and to SIGKILL on rollback.
//! - [`child_exited`] is a non-blocking liveness probe used by the
//!   readiness wait loop on the old side.
//! - [`kill_and_reap`] terminates a failed-to-start child and reaps it so
//!   it never lingers as a zombie.

use std::ffi::CString;
use std::os::raw::c_char;

use nix::sys::signal::{self, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};

use crate::WorkerError;

/// Fork the calling process and `execv` `exe_path` with `args` in the
/// child, returning the child's [`Pid`] in the parent.
///
/// `args` is the full argv vector INCLUDING `args[0]` (the program name
/// the child sees). Both the `CString` conversions AND the
/// null-terminated `argv` pointer array are built BEFORE `fork`, then the
/// child calls `libc::execv` directly. This matters: `nix::unistd::execv`
/// allocates a fresh pointer array internally (`to_exec_array`), which
/// would run in the child AFTER `fork` and is not async-signal-safe in a
/// multi-threaded (tokio) parent. Calling the raw `libc::execv` on a
/// pre-built array keeps the post-fork path allocation-free and
/// signal-safe. On `execv` failure the child calls `_exit(127)` (the
/// shell convention for "command not executable") rather than unwinding,
/// which would run `atexit` handlers inherited from the parent.
///
/// This is the engine of the hot-upgrade handoff: the old supervisor
/// forks the verified, staged binary so both processes briefly coexist
/// and share the inherited listening sockets.
pub fn fork_exec(exe_path: &str, args: &[String]) -> Result<Pid, WorkerError> {
    let exe_cstr: CString = CString::new(exe_path).map_err(|_| WorkerError::InvalidExecArg)?;
    let c_args: Vec<CString> = args
        .iter()
        .map(|s| CString::new(s.as_str()).map_err(|_| WorkerError::InvalidExecArg))
        .collect::<Result<Vec<CString>, WorkerError>>()?;
    // Null-terminated argv pointer array, built here (pre-fork) so the
    // child does no allocation. Each pointer borrows a `c_args` CString;
    // both `c_args` and `argv` outlive the call in the parent, and in the
    // child `execv` replaces the image before either could drop.
    let mut argv: Vec<*const c_char> = c_args.iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());

    // SAFETY: `fork` in a multi-threaded process leaves only the calling
    // thread running in the child. The child below performs no allocation,
    // no lock acquisition, and no async work: it calls `libc::execv` on the
    // pre-built `exe_cstr` / `argv` buffers (which replaces the image) and,
    // only if that fails, the async-signal-safe `libc::_exit`.
    match unsafe { fork() }.map_err(WorkerError::Fork)? {
        ForkResult::Parent { child } => Ok(child),
        ForkResult::Child => {
            // SAFETY: `exe_cstr` is NUL-terminated and `argv` is a
            // NUL-terminated array of pointers into live `c_args` CStrings;
            // both were fully built before the fork.
            unsafe { nix::libc::execv(exe_cstr.as_ptr(), argv.as_ptr()) };
            // SAFETY: `_exit` is async-signal-safe and the correct exit
            // path in a forked child whose `execv` failed; it skips the
            // `atexit`/`TLS` teardown that `std::process::exit` would run.
            unsafe { nix::libc::_exit(127) }
        }
    }
}

/// Non-blocking check of whether `pid` has terminated.
///
/// Returns `true` when the child has exited or was signalled (and reaps
/// it in the process), `false` while it is still alive. A `waitpid`
/// `ECHILD` (already reaped, or not our child) is treated as "exited" so
/// the caller's readiness loop never spins forever on a vanished PID.
pub fn child_exited(pid: Pid) -> bool {
    match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
        Ok(WaitStatus::StillAlive) => false,
        Ok(WaitStatus::Exited(_, _)) | Ok(WaitStatus::Signaled(_, _, _)) => true,
        Ok(_) => false,
        // ECHILD: not ours / already reaped. Any other error: be
        // conservative and report "gone" so the old side can roll back.
        Err(_) => true,
    }
}

/// SIGKILL `pid` and reap it, used on the rollback path when the freshly
/// exec'd new supervisor failed to come up. Best-effort: a kill on an
/// already-dead PID is ignored, then `waitpid` clears the zombie.
pub fn kill_and_reap(pid: Pid) {
    let _ = signal::kill(pid, Signal::SIGKILL);
    let _ = waitpid(pid, None);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_exec_rejects_arg_with_interior_nul() {
        // `/bin/true` is irrelevant here: the interior NUL is rejected
        // during CString conversion, before any fork happens.
        let bad = vec!["prog".to_string(), "a\0b".to_string()];
        let err = fork_exec("/bin/true", &bad).expect_err("interior NUL must be rejected");
        assert!(matches!(err, WorkerError::InvalidExecArg));
    }

    #[test]
    fn fork_exec_rejects_exe_with_interior_nul() {
        let err = fork_exec("/bin/\0true", &["prog".to_string()])
            .expect_err("interior NUL in exe path must be rejected");
        assert!(matches!(err, WorkerError::InvalidExecArg));
    }

    #[test]
    fn fork_exec_runs_child_and_child_exits_cleanly() {
        // Exec `/bin/true`, which exits 0 immediately. Then confirm the
        // liveness probe eventually observes the child as gone and reaps
        // it (no zombie left behind).
        let pid = fork_exec("/bin/true", &["true".to_string()])
            .expect("fork_exec of /bin/true must succeed");
        let mut gone = false;
        for _ in 0..200 {
            if child_exited(pid) {
                gone = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(gone, "child should have exited within the grace window");
    }

    #[test]
    fn kill_and_reap_terminates_a_sleeping_child() {
        // `/bin/sleep 60` would outlive the test; kill_and_reap must
        // terminate and reap it promptly.
        let pid = fork_exec("/bin/sleep", &["sleep".to_string(), "60".to_string()])
            .expect("fork_exec of /bin/sleep must succeed");
        kill_and_reap(pid);
        // After reaping, a second waitpid-based probe reports "gone".
        assert!(child_exited(pid));
    }
}
