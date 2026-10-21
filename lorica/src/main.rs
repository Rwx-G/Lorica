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

mod cli;
mod cli_automation;
mod cli_client;
mod cli_cluster;
mod cli_mcp;
mod health;
mod startup;

use clap::Parser;

use crate::cli::{
    init_logging, run_rotate_key, run_unban, run_upgrade, startup_banner, AutomationAction,
    AutomationTokenAction, Cli, ClusterAction, Commands, McpAction, McpTokenAction,
};

fn main() {
    // Explicitly set ring as the default TLS crypto provider. Ignore the
    // error if a provider was already installed (e.g. by a linked library),
    // since that is also valid.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();

    // Every Kerberos context MIT krb5 creates in this process reads the
    // `krb5.conf` Lorica generates, never the host's (Epic 13 D3). It is
    // set once, here, because MIT reads the variable at each context
    // creation and processes started from this one (workers, hot-upgrade
    // successors) inherit it. A `worker` invocation passes here too, with
    // the top-level default data directory rather than its own; workers
    // never run the API nor acquire a ticket, so that value is unused.
    //
    // SAFETY: no other thread exists yet, so nothing can read the
    // environment concurrently: `Cli::parse` spawns none, and the first
    // thread is the log appender `init_logging` may start, or a runtime
    // built after it. `set_var` is safe in edition 2021 and becomes
    // `unsafe` in edition 2024; this comment is the justification that
    // migration will need.
    std::env::set_var(
        "KRB5_CONFIG",
        lorica_adcs::krb5_config_path(std::path::Path::new(&cli.data_dir)),
    );

    match cli.command {
        Some(Commands::Worker {
            id,
            cmd_fd,
            data_dir,
            https_port,
            log_level,
            log_format,
            log_file,
            upstream_crl_file,
        }) => {
            init_logging(&log_level, &log_format, log_file.as_deref());
            startup::worker::run_worker(
                id,
                cmd_fd,
                &data_dir,
                https_port,
                upstream_crl_file.as_deref(),
            );
        }
        Some(Commands::RotateKey { new_key_file }) => {
            run_rotate_key(&cli.data_dir, &new_key_file);
        }
        Some(Commands::Unban {
            ip,
            user,
            password_file,
            password_stdin,
            password,
        }) => {
            let password =
                cli_client::read_admin_password(password, password_file.as_deref(), password_stdin)
                    .unwrap_or_else(|e| cli_client::fail(e));
            run_unban(&cli.data_dir, cli.management_port, ip, user, password);
        }
        Some(Commands::Upgrade {
            binary,
            signature,
            user,
            password_file,
            password_stdin,
            password,
        }) => {
            let password =
                cli_client::read_admin_password(password, password_file.as_deref(), password_stdin)
                    .unwrap_or_else(|e| cli_client::fail(e));
            run_upgrade(
                &cli.data_dir,
                cli.management_port,
                binary,
                signature,
                user,
                password,
            );
        }
        Some(Commands::Cluster { action }) => match action {
            ClusterAction::Init { common_name } => {
                cli_cluster::run_cluster_init(&cli.data_dir, &common_name);
            }
            ClusterAction::Join {
                control_plane,
                enrollment,
                name,
                token_file,
                token_stdin,
                server_name,
            } => {
                cli_cluster::run_cluster_join(
                    &cli.data_dir,
                    control_plane,
                    enrollment,
                    name,
                    token_file,
                    token_stdin,
                    server_name,
                );
            }
            ClusterAction::Leave {
                user,
                password_file,
                password_stdin,
                password,
            } => {
                let password = cli_client::optional_admin_password(
                    user.as_deref(),
                    password,
                    password_file.as_deref(),
                    password_stdin,
                );
                cli_cluster::run_cluster_leave(&cli.data_dir, cli.management_port, user, password);
            }
            ClusterAction::Status {
                user,
                password_file,
                password_stdin,
                password,
            } => {
                let password = cli_client::optional_admin_password(
                    user.as_deref(),
                    password,
                    password_file.as_deref(),
                    password_stdin,
                );
                cli_cluster::run_cluster_status(&cli.data_dir, cli.management_port, user, password);
            }
            ClusterAction::BreakGlass {
                duration,
                close,
                user,
                password_file,
                password_stdin,
                password,
            } => {
                let password = cli_client::read_admin_password(
                    password,
                    password_file.as_deref(),
                    password_stdin,
                )
                .unwrap_or_else(|e| cli_client::fail(e));
                cli_cluster::run_cluster_break_glass(
                    &cli.data_dir,
                    cli.management_port,
                    duration,
                    close,
                    user,
                    password,
                );
            }
            ClusterAction::Token {
                ttl_seconds,
                node_name,
                source_cidr,
                user,
                password_file,
                password_stdin,
                password,
            } => {
                let password = cli_client::read_admin_password(
                    password,
                    password_file.as_deref(),
                    password_stdin,
                )
                .unwrap_or_else(|e| cli_client::fail(e));
                cli_cluster::run_cluster_token(
                    &cli.data_dir,
                    cli.management_port,
                    ttl_seconds,
                    node_name,
                    source_cidr,
                    user,
                    password,
                );
            }
        },
        Some(Commands::Automation { action }) => match action {
            AutomationAction::Token { action } => match action {
                AutomationTokenAction::Create {
                    name,
                    scopes,
                    hostnames,
                    backend_cidrs,
                    max_ttl_seconds,
                    lifetime_days,
                    user,
                    password_file,
                    password_stdin,
                    password,
                } => {
                    let password = cli_client::read_admin_password(
                        password,
                        password_file.as_deref(),
                        password_stdin,
                    )
                    .unwrap_or_else(|e| cli_client::fail(e));
                    cli_automation::run_automation_token_create(
                        std::path::Path::new(&cli.data_dir),
                        cli.management_port,
                        &cli_automation::TokenMint {
                            name,
                            scopes,
                            hostnames,
                            backend_cidrs,
                            max_ttl_seconds,
                            lifetime_days,
                        },
                        &user,
                        &password,
                    );
                }
            },
        },
        Some(Commands::Mcp { action }) => match action {
            McpAction::Token { action } => match action {
                McpTokenAction::Create {
                    tier,
                    name,
                    hostnames,
                    backend_cidrs,
                    lifetime_days,
                    user,
                    password_file,
                    password_stdin,
                    password,
                } => {
                    let password = cli_client::read_admin_password(
                        password,
                        password_file.as_deref(),
                        password_stdin,
                    )
                    .unwrap_or_else(|e| cli_client::fail(e));
                    cli_mcp::run_mcp_token_create(
                        std::path::Path::new(&cli.data_dir),
                        cli.management_port,
                        &cli_mcp::TierMint {
                            tier,
                            name,
                            hostnames,
                            backend_cidrs,
                            lifetime_days,
                        },
                        &user,
                        &password,
                    );
                }
            },
        },
        None => {
            init_logging(&cli.log_level, &cli.log_format, cli.log_file.as_deref());
            startup_banner(&cli);

            if cli.workers.is_multi_process() {
                startup::supervisor::run_supervisor(cli);
                return;
            }

            // Single-process mode (--workers 0)
            startup::single::run_single_process(cli);
        }
    }
}

#[cfg(test)]
mod tests {
    /// Story 13.1 AC #3. `set_var` is only sound while the process has a
    /// single thread, and nothing at runtime can observe the order in
    /// which `main` did things, so the order is checked in the source:
    /// the assignment comes after `Cli::parse` and before the first
    /// `init_logging` (which may start the log appender thread) and
    /// before anything in `main.rs` that builds a runtime or a thread.
    #[test]
    fn krb5_config_is_set_before_logging_and_before_any_thread() {
        let source: &str = include_str!("main.rs");
        let production: &str = source
            .split("#[cfg(test)]")
            .next()
            .expect("test setup: main.rs has a body");
        let lines: Vec<(usize, &str)> = production
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.trim_start().starts_with("//"))
            .collect();
        let first = |needle: &str| -> Option<usize> {
            lines
                .iter()
                .find(|(_, line)| line.contains(needle))
                .map(|(index, _)| *index)
        };
        let parse: usize = first("Cli::parse()").expect("main parses the command line");
        let assignment: usize =
            first("\"KRB5_CONFIG\"").expect("main sets KRB5_CONFIG (Story 13.1 AC #3)");
        let logging: usize = first("init_logging(").expect("main initialises logging");
        assert!(
            parse < assignment,
            "KRB5_CONFIG is set before Cli::parse, which is where data_dir comes from"
        );
        assert!(
            assignment < logging,
            "KRB5_CONFIG must be set before the first init_logging, which may spawn a thread"
        );
        for marker in [
            "Runtime::new",
            "runtime::Builder",
            "new_multi_thread",
            "new_current_thread",
            "tokio::main",
            "thread::spawn",
            "thread::Builder",
        ] {
            for (index, line) in &lines {
                if line.contains(marker) {
                    assert!(
                        assignment < *index,
                        "main.rs:{}: `{marker}` runs before KRB5_CONFIG is set",
                        index + 1
                    );
                }
            }
        }
    }
}
