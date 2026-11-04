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

//! Server configurations
//!
//! Server configurations define startup settings such as:
//! * User and group to run as after daemonization
//! * Number of threads per service
//! * Error log file path

use clap::Parser;
use lorica_error::{Error, ErrorType::*, Result};
use std::ffi::OsString;

// default maximum upstream retries for retry-able proxy errors
const DEFAULT_MAX_RETRIES: usize = 16;

/// The server configuration
///
/// Lorica: built in code only. Upstream also loads it from a YAML file
/// named by the `-c` flag; that path is removed (see `FORK.md`), so start
/// from [`ServerConf::new`] or [`ServerConf::default`] and set fields.
#[derive(Debug, PartialEq, Eq)]
pub struct ServerConf {
    /// Version
    pub version: usize,
    /// Whether to run this process in the background.
    pub daemon: bool,
    /// When configured and `daemon` setting is `true`, error log will be written to the given
    /// file. Otherwise StdErr will be used.
    pub error_log: Option<String>,
    /// The pid (process ID) file of this server to be created when running in background
    pub pid_file: String,
    /// the path to the upgrade socket
    ///
    /// In order to perform zero downtime restart, both the new and old process need to agree on the
    /// path to this sock in order to coordinate the upgrade.
    pub upgrade_sock: String,
    /// If configured, after daemonization, this process will switch to the given user before
    /// starting to serve traffic.
    pub user: Option<String>,
    /// Similar to `user`, the group this process should switch to.
    pub group: Option<String>,
    /// How many threads **each** service should get. The threads are not shared across services.
    pub threads: usize,
    /// Number of listener tasks to use per fd. This allows for parallel accepts.
    pub listener_tasks_per_fd: usize,
    /// Allow work stealing between threads of the same service. Default `true`.
    pub work_stealing: bool,
    /// The path to CA file the SSL library should use. If empty, the default trust store location
    /// defined by the SSL library will be used.
    pub ca_file: Option<String>,
    /// Grace period in seconds before starting the final step of the graceful shutdown after signaling shutdown.
    pub grace_period_seconds: Option<u64>,
    /// Timeout in seconds of the final step for the graceful shutdown.
    pub graceful_shutdown_timeout_seconds: Option<u64>,
    // These options don't belong here as they are specific to certain services
    /// IPv4 addresses for a client connector to bind to. See
    /// [`ConnectorOptions`](crate::connectors::ConnectorOptions).
    /// Note: this is an _unstable_ field that may be renamed or removed in the future.
    pub client_bind_to_ipv4: Vec<String>,
    /// IPv6 addresses for a client connector to bind to. See
    /// [`ConnectorOptions`](crate::connectors::ConnectorOptions).
    /// Note: this is an _unstable_ field that may be renamed or removed in the future.
    pub client_bind_to_ipv6: Vec<String>,
    /// Keepalive pool size for client connections to upstream. See
    /// [`ConnectorOptions`](crate::connectors::ConnectorOptions).
    /// Note: this is an _unstable_ field that may be renamed or removed in the future.
    pub upstream_keepalive_pool_size: usize,
    /// Number of dedicated thread pools to use for upstream connection establishment.
    /// See [`ConnectorOptions`](crate::connectors::ConnectorOptions).
    /// Note: this is an _unstable_ field that may be renamed or removed in the future.
    pub upstream_connect_offload_threadpools: Option<usize>,
    /// Number of threads per dedicated upstream connection establishment pool.
    /// See [`ConnectorOptions`](crate::connectors::ConnectorOptions).
    /// Note: this is an _unstable_ field that may be renamed or removed in the future.
    pub upstream_connect_offload_thread_per_pool: Option<usize>,
    /// When enabled allows TLS keys to be written to a file specified by the SSLKEYLOG
    /// env variable. This can be used by tools like Wireshark to decrypt upstream traffic
    /// for debugging purposes.
    /// Note: this is an _unstable_ field that may be renamed or removed in the future.
    pub upstream_debug_ssl_keylog: bool,
    /// The maximum number of retries that will be attempted when an error is
    /// retry-able (`e.retry() == true`) when proxying to upstream.
    ///
    /// This setting is a fail-safe and defaults to 16.
    pub max_retries: usize,
    /// Maximum number of retries for upgrade socket connect and accept operations.
    /// This controls how many times send_fds_to will retry connecting and how many times
    /// get_fds_from will retry accepting during graceful upgrades.
    /// The retry interval is 1 second between attempts.
    /// If not set, defaults to 5 retries.
    pub upgrade_sock_connect_accept_max_retries: Option<usize>,
    /// The maximum number of threads in each runtime's blocking thread pool.
    ///
    /// The blocking pool handles [`tokio::task::spawn_blocking`] tasks.
    /// When not set, the tokio default (512) is used.
    pub max_blocking_threads: Option<usize>,
    /// How long, in seconds, idle blocking threads are kept alive before being shut down.
    ///
    /// When not set, the tokio default (10 seconds) is used.
    pub blocking_threads_ttl_seconds: Option<u64>,
    /// Path to a CRL (Certificate Revocation List) file in PEM or DER format.
    /// When set, upstream server certificates are checked against this CRL.
    pub upstream_crl_file: Option<String>,
}

impl Default for ServerConf {
    fn default() -> Self {
        ServerConf {
            version: 0,
            client_bind_to_ipv4: vec![],
            client_bind_to_ipv6: vec![],
            ca_file: None,
            daemon: false,
            error_log: None,
            upstream_debug_ssl_keylog: false,
            pid_file: "/tmp/lorica.pid".to_string(),
            upgrade_sock: "/tmp/lorica_upgrade.sock".to_string(),
            user: None,
            group: None,
            threads: 1,
            listener_tasks_per_fd: 1,
            work_stealing: true,
            upstream_keepalive_pool_size: 128,
            upstream_connect_offload_threadpools: None,
            upstream_connect_offload_thread_per_pool: None,
            grace_period_seconds: None,
            graceful_shutdown_timeout_seconds: None,
            max_retries: DEFAULT_MAX_RETRIES,
            upgrade_sock_connect_accept_max_retries: None,
            max_blocking_threads: None,
            blocking_threads_ttl_seconds: None,
            upstream_crl_file: None,
        }
    }
}

/// Command-line options
///
/// Call `Opt::parse_args()` to build this object from the process's command line arguments.
#[derive(Parser, Debug, Default)]
#[clap(name = "basic", long_about = None)]
pub struct Opt {
    /// Whether this server should try to upgrade from a running old server
    #[clap(
        short,
        long,
        help = "This is the base set of command line arguments for a lorica-based service",
        long_help = None
    )]
    pub upgrade: bool,

    /// Whether this server should run in the background
    #[clap(short, long)]
    pub daemon: bool,

    /// Not actually used. This flag is there so that the server is not upset seeing this flag
    /// passed from `cargo test` sometimes
    #[clap(long, hide = true)]
    pub nocapture: bool,

    /// Test the configuration and exit
    ///
    /// When this flag is set, calling `server.bootstrap()` will exit the process without errors
    ///
    /// This flag is useful for upgrading service where the user wants to make sure the new
    /// service can start before shutting down the old server process.
    #[clap(
        short,
        long,
        help = "This flag is useful for upgrading service where the user wants \
                to make sure the new service can start before shutting down \
                the old server process.",
        long_help = None
    )]
    pub test: bool,
}

impl ServerConf {
    /// The configuration a [`Server`](crate::server::Server) starts with:
    /// [`ServerConf::default`] with `version` 1.
    ///
    /// Lorica: upstream builds it by parsing the YAML document
    /// `version: 1` over the serde defaults, which are exactly
    /// [`ServerConf::default`]; this constructs the same value directly.
    pub fn new() -> Self {
        ServerConf {
            version: 1,
            ..Default::default()
        }
    }

    /// [`ServerConf::new`] with the command-line overrides of `opt` applied.
    pub fn new_with_opt_override(opt: &Opt) -> Self {
        let mut conf = Self::new();
        conf.merge_with_opt(opt);
        conf
    }

    /// Reject values the server cannot run with.
    pub fn validate(self) -> Result<Self> {
        if self.max_blocking_threads == Some(0) {
            return Error::e_explain(ReadError, "max_blocking_threads must be greater than zero");
        }
        Ok(self)
    }

    pub fn merge_with_opt(&mut self, opt: &Opt) {
        if opt.daemon {
            self.daemon = true;
        }
    }
}

/// Create an instance of Opt by parsing the current command-line args.
/// This is equivalent to running `Opt::parse` but does not require the
/// caller to have included the `clap::Parser`
impl Opt {
    pub fn parse_args() -> Self {
        Opt::parse()
    }

    pub fn parse_from_args<I, T>(args: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        Opt::parse_from(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_log() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_new_pins_the_defaults() {
        let expected = ServerConf {
            version: 1,
            daemon: false,
            error_log: None,
            pid_file: "/tmp/lorica.pid".to_string(),
            upgrade_sock: "/tmp/lorica_upgrade.sock".to_string(),
            user: None,
            group: None,
            threads: 1,
            listener_tasks_per_fd: 1,
            work_stealing: true,
            ca_file: None,
            grace_period_seconds: None,
            graceful_shutdown_timeout_seconds: None,
            client_bind_to_ipv4: vec![],
            client_bind_to_ipv6: vec![],
            upstream_keepalive_pool_size: 128,
            upstream_connect_offload_threadpools: None,
            upstream_connect_offload_thread_per_pool: None,
            upstream_debug_ssl_keylog: false,
            max_retries: 16,
            upgrade_sock_connect_accept_max_retries: None,
            max_blocking_threads: None,
            blocking_threads_ttl_seconds: None,
            upstream_crl_file: None,
        };
        assert_eq!(expected, ServerConf::new());
        assert_eq!(expected, ServerConf::new().validate().unwrap());
    }

    #[test]
    fn test_opt_override_sets_daemon() {
        init_log();
        let opt = Opt::parse_from_args(["lorica", "-d"]);
        assert!(ServerConf::new_with_opt_override(&opt).daemon);
        assert!(!ServerConf::new_with_opt_override(&Opt::default()).daemon);
    }

    #[test]
    fn test_conf_flag_is_gone() {
        init_log();
        assert!(Opt::try_parse_from(["lorica", "-c", "conf.yaml"]).is_err());
    }

    #[test]
    fn test_zero_max_blocking_threads_is_rejected() {
        init_log();
        let conf = ServerConf {
            max_blocking_threads: Some(0),
            ..ServerConf::new()
        };
        assert!(
            conf.validate().is_err(),
            "max_blocking_threads: 0 should fail validation"
        );
    }

    #[test]
    fn test_valid_max_blocking_threads() {
        init_log();
        let conf = ServerConf {
            max_blocking_threads: Some(64),
            blocking_threads_ttl_seconds: Some(30),
            ..ServerConf::new()
        }
        .validate()
        .unwrap();
        assert_eq!(Some(64), conf.max_blocking_threads);
        assert_eq!(Some(30), conf.blocking_threads_ttl_seconds);
    }
}
