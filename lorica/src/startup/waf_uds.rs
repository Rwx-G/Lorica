// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Supervisor-side WAF UDS event listener.
//!
//! Workers forward `lorica_waf::WafEvent` JSON lines over a per-data-
//! dir Unix domain socket (`<data-dir>/waf.sock`). The supervisor :
//! - Buffers events for the `/api/v1/waf/events` endpoint (bounded
//!   ring at 500 entries to cap memory under flood).
//! - Dispatches one `WafAlert` notification per event.
//! - Increments the cross-worker shmem auto-ban counter for each
//!   event's `client_ip` ; on threshold cross, broadcasts a `BanIp`
//!   to every worker and resets the slot. The supervisor is the
//!   sole ban-issuer so the ban is consistent across the pool.
//!
//! Story 8.1 AC #1+#3 - moved out of `run_supervisor` (was ~138 LOC
//! inline) to keep the supervisor boot path readable.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::Arc;

use tokio::sync::broadcast;
use tokio::sync::Mutex;
use tracing::warn;

use lorica_config::ConfigStore;
use lorica_notify::AlertSender;
use lorica_shmem::SharedRegion;

/// Bind the supervisor's WAF UDS socket and spawn the event listener
/// loop. Old socket file is removed before bind ; permissions are set
/// to `0o660` so non-root workers can connect.
///
/// The function panics on bind failure (this is part of supervisor
/// boot ; failing here means the install is broken). Subsequent
/// per-connection spawn errors are logged + the loop continues.
pub fn spawn_waf_uds_listener(
    data_dir: &Path,
    waf_event_sink: Arc<parking_lot::Mutex<VecDeque<lorica_waf::WafEvent>>>,
    alert_sender: AlertSender,
    shmem: &'static SharedRegion,
    ban_tx: broadcast::Sender<(String, u64)>,
    ban_store: Arc<Mutex<ConfigStore>>,
) {
    let waf_sock_path = data_dir.join("waf.sock");
    let _ = std::fs::remove_file(&waf_sock_path);
    let waf_listener = tokio::net::UnixListener::bind(&waf_sock_path)
        .expect("failed to bind WAF socket");
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&waf_sock_path, std::fs::Permissions::from_mode(0o660));
    }

    tokio::spawn(async move {
        loop {
            match waf_listener.accept().await {
                Ok((stream, _)) => {
                    let sink = Arc::clone(&waf_event_sink);
                    let alert_tx = alert_sender.clone();
                    let ban_tx = ban_tx.clone();
                    let ban_store = Arc::clone(&ban_store);
                    tokio::spawn(async move {
                        let mut reader = tokio::io::BufReader::new(stream);
                        let mut line = String::new();
                        loop {
                            line.clear();
                            match tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line).await {
                                Ok(0) => break,
                                Ok(_) => {
                                    if let Ok(event) = serde_json::from_str::<lorica_waf::WafEvent>(&line) {
                                        // Workers insert WAF events into the DB directly
                                        // (with route_hostname and action stamped), so we
                                        // skip the insert here to avoid duplicates.

                                        // Dispatch WAF alert notification
                                        alert_tx.send(
                                            lorica_notify::AlertEvent::new(
                                                lorica_notify::events::AlertType::WafAlert,
                                                format!("WAF {}: {} (rule {})", event.category.as_str(), event.description, event.rule_id),
                                            )
                                            .with_detail("rule_id", event.rule_id.to_string())
                                            .with_detail("category", event.category.as_str().to_string())
                                            .with_detail("severity", event.severity.to_string()),
                                        );

                                        // Global WAF auto-ban: read the cross-worker shmem
                                        // counter. Workers have already bumped it in their
                                        // hot path (see proxy_wiring.rs). The supervisor
                                        // compares against the configured threshold and,
                                        // on the first crossing, broadcasts BanIp and
                                        // resets the slot so the next round starts at zero.
                                        //
                                        // Concurrent UDS events for the same IP can race:
                                        // task A reads shmem >= threshold, decides to ban,
                                        // resets; task B reads (post-A's read, pre-A's
                                        // reset) ALSO sees >= threshold and broadcasts a
                                        // duplicate BanIp. The race is bounded by the
                                        // burst size of WAF events for one IP within a few
                                        // microseconds, and the duplicate broadcast is
                                        // idempotent (DashMap insert + same duration). The
                                        // ban_list arrives at every worker exactly the
                                        // same way; the only effect is one extra notify
                                        // alert dispatch. Acceptable.
                                        if !event.client_ip.is_empty() && event.client_ip != "-" {
                                            let s = ban_store.lock().await;
                                            let (threshold, duration_s) = s.get_global_settings()
                                                .map(|gs| (gs.waf_ban_threshold as u64, gs.waf_ban_duration_s as u64))
                                                .unwrap_or((0, 600));
                                            drop(s);

                                            if threshold > 0 {
                                                let key = lorica::proxy_wiring::ip_to_shmem_key(
                                                    &event.client_ip,
                                                );
                                                let tagged = shmem.tagged(key);
                                                let count = shmem
                                                    .waf_auto_ban
                                                    .read(tagged)
                                                    .unwrap_or(0);
                                                if count >= threshold {
                                                    // Reset slot so concurrent/future
                                                    // violations after broadcast start
                                                    // fresh. CAS failure is benign (another
                                                    // event raced and we already broadcast).
                                                    let _ = shmem
                                                        .waf_auto_ban
                                                        .reset(tagged);
                                                    warn!(
                                                        ip = %event.client_ip,
                                                        violations = %count,
                                                        ban_duration_s = %duration_s,
                                                        "global WAF auto-ban: IP banned for repeated violations"
                                                    );
                                                    // Broadcast BanIp to all workers
                                                    let _ = ban_tx.send((event.client_ip.clone(), duration_s));
                                                    // Dispatch ip_banned alert
                                                    alert_tx.send(
                                                        lorica_notify::AlertEvent::new(
                                                            lorica_notify::events::AlertType::IpBanned,
                                                            format!(
                                                                "IP {} auto-banned for repeated WAF violations",
                                                                event.client_ip
                                                            ),
                                                        )
                                                        .with_detail("ip", event.client_ip.clone())
                                                        .with_detail("violations", count.to_string())
                                                        .with_detail("ban_duration_s", duration_s.to_string()),
                                                    );
                                                }
                                            }
                                        }

                                        let mut buf = sink.lock();
                                        if buf.len() >= 500 {
                                            buf.pop_front();
                                        }
                                        buf.push_back(event);
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "WAF socket accept failed");
                }
            }
        }
    });
}
