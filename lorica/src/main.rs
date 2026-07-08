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
mod health;
mod startup;

use clap::Parser;

use crate::cli::{
    init_logging, run_rotate_key, run_unban, run_upgrade, startup_banner, Cli, Commands,
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
