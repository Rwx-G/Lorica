// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! `lorica unban <ip>` subcommand : remove an IP from the auto-ban
//! list via the management API.
//!
//! Logs in as the configured admin user, then issues
//! `DELETE /api/v1/bans/<ip>`. Exits non-zero on any failure (login
//! refused, network error, unban refused).

/// Run the `unban` subcommand.
///
/// `management_port` is the resolved `--management-port` (CLI flag or
/// default 9443). `ip`, `user`, `password` are the subcommand args.
pub fn run(management_port: u16, ip: &str, user: &str, password: &str) {
    let port = management_port;
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .cookie_store(true)
            .build()
            .expect("HTTP client");

        // Login
        let login_url = format!("https://127.0.0.1:{port}/api/v1/auth/login");
        let login_res = client
            .post(&login_url)
            .json(&serde_json::json!({ "username": user, "password": password }))
            .send()
            .await;
        match login_res {
            Ok(r) if r.status().is_success() => {}
            Ok(r) => {
                eprintln!("Login failed ({}). Check credentials.", r.status());
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("Cannot connect to management API on port {port}: {e}");
                std::process::exit(1);
            }
        }

        // Unban
        let unban_url = format!("https://127.0.0.1:{port}/api/v1/bans/{ip}");
        match client.delete(&unban_url).send().await {
            Ok(r) if r.status().is_success() => {
                println!("IP {ip} unbanned successfully.");
            }
            Ok(r) => {
                let body = r.text().await.unwrap_or_default();
                eprintln!("Unban failed: {body}");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("Unban request failed: {e}");
                std::process::exit(1);
            }
        }
    });
}
