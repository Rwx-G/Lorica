// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Supervisor-side log UDS listener.
//!
//! Workers serialise `lorica_api::logs::LogEntry` to JSON lines and
//! send them across `<data-dir>/log.sock` to the supervisor. The
//! supervisor pushes each entry into the in-memory `LogBuffer` so the
//! dashboard's WebSocket log stream can serve it. Workers persist
//! access logs to their own `LogStore` directly, so the listener
//! does NOT touch SQLite (avoids duplicate inserts under multi-worker).

use std::path::Path;
use std::sync::Arc;

use lorica_api::logs::LogBuffer;

/// Bind the supervisor's log UDS socket and spawn the forwarder loop.
/// Old socket file is removed before bind ; permissions set to
/// `0o660` so non-root workers can write.
///
/// Panics on bind failure (supervisor boot path - failing here means
/// the install is broken). Per-connection accept errors are logged
/// + the loop continues.
pub fn spawn_log_uds_listener(data_dir: &Path, log_buffer: Arc<LogBuffer>) {
    let log_sock_path = data_dir.join("log.sock");
    let _ = std::fs::remove_file(&log_sock_path);
    let log_listener = tokio::net::UnixListener::bind(&log_sock_path)
        .expect("failed to bind log socket");
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&log_sock_path, std::fs::Permissions::from_mode(0o660));
    }

    tokio::spawn(async move {
        loop {
            match log_listener.accept().await {
                Ok((stream, _)) => {
                    let sink = Arc::clone(&log_buffer);
                    tokio::spawn(async move {
                        let mut reader = tokio::io::BufReader::new(stream);
                        let mut line = String::new();
                        loop {
                            line.clear();
                            match tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line).await {
                                Ok(0) => break, // EOF - worker disconnected
                                Ok(_) => {
                                    if let Ok(entry) = serde_json::from_str::<lorica_api::logs::LogEntry>(&line) {
                                        // Workers persist access logs directly via their own
                                        // LogStore, so we only push to the in-memory buffer
                                        // here (for WebSocket streaming to the dashboard).
                                        sink.push(entry);
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "log socket accept failed");
                }
            }
        }
    });
}
