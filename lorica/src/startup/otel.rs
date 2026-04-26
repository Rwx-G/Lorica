// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! OpenTelemetry exporter boot helper.
//!
//! Reads the persisted `GlobalSettings.otlp_*` fields from the store
//! and, when `otlp_endpoint` is non-empty, calls
//! [`lorica::otel::init`] which installs the global tracer provider
//! and unblocks the reload hook the logging subscriber set up. A
//! missing endpoint is the normal "OTel disabled" path - the function
//! quietly returns. A failed `init` is logged at warn but does not
//! abort startup.

use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::{info, warn};

use lorica_config::ConfigStore;

/// Try to initialise the OpenTelemetry exporter from persisted
/// `GlobalSettings`. No-op when the `otel` Cargo feature is off, the
/// settings row cannot be read, or `otlp_endpoint` is unset / blank.
///
/// Must be called from inside a Tokio runtime - the OTLP batch
/// exporter latches onto the current runtime at construction.
pub async fn try_init_from_settings(store: &Arc<Mutex<ConfigStore>>, role: &str) {
    let s = store.lock().await;
    let gs = match s.get_global_settings() {
        Ok(gs) => gs,
        Err(e) => {
            warn!(error = %e, "failed to read global settings for OTel init");
            return;
        }
    };
    drop(s);

    let Some(endpoint) = gs.otlp_endpoint.as_ref().filter(|e| !e.trim().is_empty()) else {
        return;
    };

    let otel_cfg = lorica::otel::OtelConfig {
        endpoint: endpoint.clone(),
        protocol: lorica::otel::OtlpProtocol::from_settings(&gs.otlp_protocol),
        service_name: gs.otlp_service_name.clone(),
        sampling_ratio: gs.otlp_sampling_ratio,
    };
    match lorica::otel::init(&otel_cfg) {
        Ok(()) => info!(
            role = role,
            endpoint = %otel_cfg.endpoint,
            protocol = otel_cfg.protocol.as_str(),
            service_name = %otel_cfg.service_name,
            sampling_ratio = otel_cfg.sampling_ratio,
            "OpenTelemetry tracing enabled"
        ),
        Err(e) => warn!(
            role = role,
            error = %e,
            "OpenTelemetry init failed; tracing disabled (startup continues)"
        ),
    }
}
