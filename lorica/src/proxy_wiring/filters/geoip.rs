// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! GeoIP `check_<name>` helper. Resolves the client country via the
//! loaded mmdb database, stamps it on the OTel root span for traffic
//! analytics, and rejects with 403 when the route's `geoip` config
//! blocks the resolved country (allowlist or denylist mode). Returns
//! the cached country alongside the decision so the caller can reuse
//! it for downstream bot-protection bypass matching without a second
//! mmdb decode.

use std::sync::Arc;

use super::super::context::RequestCtx;
use super::super::error_pages::Decision;
use super::super::routing::RouteEntry;
use super::super::LoricaProxy;

impl LoricaProxy {
    /// Resolve the client's GeoIP country (when a DB is loaded), record
    /// it on the OTel root span for traffic analytics, and reject with
    /// 403 when the route's `geoip` config blocks the resolved country.
    /// Returns `(cached_country, decision)` so the caller can reuse
    /// the resolved country for downstream bot-protection bypass
    /// matching without paying a redundant `mmdb decode_path` call.
    pub(crate) fn check_geoip(
        &self,
        ctx: &mut RequestCtx,
        entry: &Arc<RouteEntry>,
        client_ip: Option<&str>,
    ) -> (Option<String>, Option<Decision>) {
        let Some(ip_str) = client_ip else {
            return (None, None);
        };
        let Ok(ip_addr) = ip_str.parse::<std::net::IpAddr>() else {
            return (None, None);
        };
        let Some(country) = self.geoip_resolver.lookup_country(ip_addr) else {
            // DB miss / unknown range; fall through without blocking.
            // No OTel attribute when country is unknown - omitting is
            // semantically clearer than setting an empty string.
            return (None, None);
        };
        let cached_country = country.as_str().to_string();
        // Always stamp the country on the root tracing span -- the
        // attribute is useful even on requests that are not blocked
        // (traffic analytics per country, anomaly detection).
        ctx.root_tracing_span
            .record("client.geo.country_iso_code", country.as_str());

        let Some(ref geoip_cfg) = entry.route.geoip else {
            return (Some(cached_country), None);
        };
        if !geoip_cfg.blocks(country.as_str()) {
            return (Some(cached_country), None);
        }
        use lorica_config::models::GeoIpMode;
        let mode_str = match geoip_cfg.mode {
            GeoIpMode::Allowlist => "allowlist",
            GeoIpMode::Denylist => "denylist",
        };
        // Prometheus counter: bounded cardinality (routes * ~240
        // countries * 2 modes). Use entry.route.id directly - the
        // per-request ctx.route_id is only assigned further down the
        // filter (after response_headers + auth checks) and would
        // show up as "_unknown" here.
        lorica_api::metrics::inc_geoip_block(
            entry.route.id.as_str(),
            country.as_str(),
            mode_str,
        );
        let reason = format!("GeoIP blocked ({country} via {mode_str})");
        ctx.block_reason = Some(reason.clone());
        (
            Some(cached_country),
            Some(
                Decision::reject(403, reason)
                    .with_html(entry.route.error_page_html.clone()),
            ),
        )
    }
}
