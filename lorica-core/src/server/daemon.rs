// Copyright 2026 Cloudflare, Inc.
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

use log::warn;

use crate::server::configuration::ServerConf;

// Utilities to daemonize a lorica server.
//
// The upstream `daemonize = "0.5"` dep was dropped in v1.3.0 because
// RUSTSEC-2025-0069 flagged it unmaintained and single-maintainer
// (audit). Production Lorica deployments run under systemd with
// `Type=simple` (see `dist/lorica.service`), which is the supported
// and documented path - systemd handles user/group drop, working
// directory, pid file, and stdio redirection via the unit file. The
// legacy `--daemon` flag now only emits a warning and falls through
// to foreground execution; existing callers that went through
// `daemonize()` will keep running as a regular process.
//
// If a re-implementation is ever needed (operators running Lorica
// outside systemd on a bare init), the right answer is inline
// double-fork + `setsid` + pid-file write + `setuid/setgid` with
// careful error handling. See
// `lorica-core::server::configuration::ServerConf` for the fields
// that would drive it.

/// Legacy daemonize entry point. No longer forks; emits a warning
/// and returns so the caller continues running in the foreground.
#[cfg(unix)]
pub fn daemonize(conf: &ServerConf) {
    if !conf.pid_file.is_empty() || conf.user.is_some() || conf.group.is_some() {
        warn!(
            "lorica-core: --daemon mode is no longer supported by this build \
             (daemonize dep was removed in v1.3.0 due to RUSTSEC-2025-0069 \
             supply-chain concern). Run under systemd with Type=simple instead \
             (dist/lorica.service). Process continues in foreground."
        );
    }
}
