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

//! The process's shutdown signal, for its periodic background loops.
//!
//! The exit path closes the shared task tracker and waits for it, so
//! that work in flight (a backend drain, a load test, a session write)
//! finishes before the process exits. A periodic loop (the blocklist
//! refresh, the certificate checks, the prunes) is not work in flight:
//! it never ends by itself, and while it was tracked every exit waited
//! out the whole drain timeout for it. Each such loop waits on [`tick`]
//! or [`sleep`] instead of the bare timer, so it ends as soon as
//! [`begin`] is called.
//!
//! One signal per process, because a process stops once: the stop and
//! upgrade paths call [`begin`], nothing else does.

use std::sync::LazyLock;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

static SHUTDOWN: LazyLock<CancellationToken> = LazyLock::new(CancellationToken::new);

/// Start the process's shutdown: every loop waiting on [`tick`],
/// [`sleep`] or [`token`] ends.
pub fn begin() {
    SHUTDOWN.cancel();
}

/// A handle on the shutdown signal, for a loop that selects on it.
pub fn token() -> CancellationToken {
    SHUTDOWN.clone()
}

/// Wait for the next tick of `ticker`. Returns `false` instead once the
/// shutdown has begun, so a loop reads `while shutdown::tick(&mut t).await`.
pub async fn tick(ticker: &mut tokio::time::Interval) -> bool {
    tokio::select! {
        biased;
        _ = SHUTDOWN.cancelled() => false,
        _ = ticker.tick() => true,
    }
}

/// Sleep for `duration`. Returns `false` instead once the shutdown has
/// begun.
pub async fn sleep(duration: Duration) -> bool {
    tokio::select! {
        biased;
        _ = SHUTDOWN.cancelled() => false,
        _ = tokio::time::sleep(duration) => true,
    }
}
