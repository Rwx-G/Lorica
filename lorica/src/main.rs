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
mod cli_client;
mod cli_cluster;
mod health;
mod startup;

use clap::Parser;

use crate::cli::{
    init_logging, run_rotate_key, run_unban, run_upgrade, startup_banner, Cli,
    ClusterAction, Commands,
};

fn main() {
    // Explicitly set ring as the default TLS crypto provider. Ignore the
    // error if a provider was already installed (e.g. by a linked library),
    // since that is also valid.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();

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
        Some(Commands::Unban { ip, user, password }) => {
            run_unban(cli.management_port, ip, user, password);
        }
        Some(Commands::Upgrade {
            binary,
            signature,
            user,
            password,
        }) => {
            run_upgrade(cli.management_port, binary, signature, user, password);
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
                let password = user.as_ref().map(|_| {
                    cli_client::read_admin_password(password, password_file.as_deref(), password_stdin)
                        .unwrap_or_else(|e| cli_client::fail(e))
                });
                cli_cluster::run_cluster_leave(&cli.data_dir, cli.management_port, user, password);
            }
            ClusterAction::Status {
                user,
                password_file,
                password_stdin,
                password,
            } => {
                let password = user.as_ref().map(|_| {
                    cli_client::read_admin_password(password, password_file.as_deref(), password_stdin)
                        .unwrap_or_else(|e| cli_client::fail(e))
                });
                cli_cluster::run_cluster_status(&cli.data_dir, cli.management_port, user, password);
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
                let password =
                    cli_client::read_admin_password(password, password_file.as_deref(), password_stdin)
                        .unwrap_or_else(|e| cli_client::fail(e));
                cli_cluster::run_cluster_token(
                    cli.management_port,
                    ttl_seconds,
                    node_name,
                    source_cidr,
                    user,
                    password,
                );
            }
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
