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

//! The frozen v1.7.0 wire corpus (Epic 9 close, architecture review).
//!
//! `rust_tags_match_the_published_proto` in `messages.rs` pins every
//! field NUMBER against `cluster.proto`. It cannot notice a field whose
//! type, meaning or presence changed under the same number, and a
//! mixed-version fleet is exactly where that matters: the peer on the
//! other end may be one release behind and holds the OLD encoding.
//!
//! So this file freezes one instance of every message the protocol
//! carries, encoded by the build that shipped v1.7.0, in
//! `tests/fixtures/wire-corpus-v1.txt`. Two properties are asserted:
//!
//! - **Encoding stability.** The current build encodes each instance
//!   to exactly the frozen bytes. A change here is a wire change, and
//!   the change must decide whether it is compatible before it is
//!   allowed to update the fixture.
//! - **Decoding stability.** The current build decodes the frozen bytes
//!   back to exactly the instance. This is the direction that protects
//!   a fleet: it is what a v1.7.0 peer will send.
//!
//! When a field is ADDED, its instance here gains a value, the fixture
//! for that message changes, and both directions must still hold for
//! the OLD bytes: add the previous line back under a `-v1` suffix
//! rather than replacing it, so the old encoding stays a test case.
//!
//! Regenerate with
//! `cargo test -p lorica-cluster --test wire_corpus regenerate -- --ignored --nocapture`
//! and paste the printed block into the fixture file, after deciding
//! the change is compatible.

use lorica_cluster::messages::{
    cluster_frame, cluster_request, cluster_response, BanPush, BanPushAck, CertMaterial, CertPull,
    CertPullAck, CertPush, CertPushAck, CertRefusal, ChallengePublish, ChallengePublishAck,
    ChallengeRetract, ChallengeRetractAck, ClusterFrame, ClusterRequest, ClusterResponse,
    ConfigAbort, ConfigAbortAck, ConfigCommit, ConfigCommitAck, ConfigPrepare, ConfigPrepareAck,
    ConfigPull, ConfigPullAck, Enroll, EnrollAck, Heartbeat, HeartbeatAck, Hello, HelloAck, Leave,
    LeaveAck, NodeResources, Renew, RenewAck, SlaBucketRow, SlaPull, SlaPullAck, SlaSummaryRow,
    TelemetryAccessRow, TelemetryAuditRow, TelemetryBan, TelemetryPush, TelemetryPushAck,
    TelemetryWafRow,
};
use prost::Message;
use std::collections::BTreeMap;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/wire-corpus-v1.txt"
);

/// Decodes frozen bytes and says whether they equal the instance.
type RoundTrip = Box<dyn Fn(&[u8]) -> Result<bool, String>>;

/// One corpus entry: the name, the bytes this build produces, and a
/// decoder that says whether `bytes` decode back to the instance.
struct Entry {
    name: &'static str,
    encoded: Vec<u8>,
    round_trips: RoundTrip,
}

fn entry<M>(name: &'static str, message: M) -> Entry
where
    M: Message + PartialEq + Default + 'static,
{
    let encoded = message.encode_to_vec();
    Entry {
        name,
        encoded,
        round_trips: Box::new(move |bytes| {
            M::decode(bytes)
                .map(|decoded| decoded == message)
                .map_err(|e| e.to_string())
        }),
    }
}

fn pem(kind: &str) -> String {
    format!("-----BEGIN {kind}-----\nAA==\n-----END {kind}-----\n")
}

fn hex64(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

fn cert_material() -> CertMaterial {
    CertMaterial {
        cert_id: "cert-1".to_string(),
        domain: "fleet.example.com".to_string(),
        cert_pem: pem("CERTIFICATE"),
        key_pem: pem("PRIVATE KEY"),
        key_digest: format!("sha256:{}", hex64('0')),
    }
}

fn resources() -> NodeResources {
    NodeResources {
        cpu_percent: 42,
        memory_used_bytes: 1 << 30,
        memory_total_bytes: 4 << 30,
        disk_used_bytes: 10 << 30,
        disk_total_bytes: 100 << 30,
    }
}

fn heartbeat() -> Heartbeat {
    Heartbeat {
        timestamp_ms: 1_757_400_000_000,
        applied_generation: 7,
        applied_hash: "sha256:ab12".to_string(),
        break_glass: true,
        resources: Some(resources()),
    }
}

fn heartbeat_ack() -> HeartbeatAck {
    HeartbeatAck {
        timestamp_ms: 1_757_400_000_000,
        fleet_size_hint: 3,
        current_generation: 8,
        current_hash: "sha256:cd34".to_string(),
    }
}

fn access_row() -> TelemetryAccessRow {
    TelemetryAccessRow {
        timestamp: "2026-09-09T10:00:00Z".to_string(),
        method: "GET".to_string(),
        path: "/".to_string(),
        host: "fleet.example.com".to_string(),
        status: 502,
        latency_ms: 12,
        backend: "be-1".to_string(),
        error: "upstream timeout".to_string(),
        client_ip: "192.0.2.10".to_string(),
        is_xff: true,
        xff_proxy_ip: "192.0.2.1".to_string(),
        source: "proxy".to_string(),
        request_id: "req-1".to_string(),
    }
}

fn waf_row() -> TelemetryWafRow {
    TelemetryWafRow {
        rule_id: 942_100,
        description: "SQL injection".to_string(),
        category: "sqli".to_string(),
        severity: 5,
        matched_field: "query".to_string(),
        matched_value: "1 OR 1=1".to_string(),
        timestamp: "2026-09-09T10:00:01Z".to_string(),
        client_ip: "192.0.2.10".to_string(),
        route_hostname: "fleet.example.com".to_string(),
        action: "block".to_string(),
    }
}

fn ban() -> TelemetryBan {
    TelemetryBan {
        client_ip: "192.0.2.10".to_string(),
        remaining_s: 600,
        reason: "waf".to_string(),
    }
}

fn audit_row() -> TelemetryAuditRow {
    TelemetryAuditRow {
        origin_id: 41,
        timestamp: "2026-09-09T10:00:02Z".to_string(),
        operator_username: "admin".to_string(),
        operator_role: "super_admin".to_string(),
        action: "cluster.config.apply".to_string(),
        target_type: "cluster_config".to_string(),
        target_id: "8".to_string(),
        before_payload_hash: hex64('a'),
        after_payload_hash: hex64('b'),
        ip: "192.0.2.10".to_string(),
        user_agent: "curl".to_string(),
        prev_chain_hash: hex64('c'),
        chain_hash: hex64('d'),
    }
}

fn telemetry_push() -> TelemetryPush {
    TelemetryPush {
        access: vec![access_row()],
        waf: vec![waf_row()],
        bans: vec![ban()],
        access_cursor: 1001,
        waf_cursor: 77,
        dropped_since_last: 3,
        audit: vec![audit_row()],
        audit_cursor: 41,
    }
}

fn sla_summary() -> SlaSummaryRow {
    SlaSummaryRow {
        route_id: "route-1".to_string(),
        window: "1h".to_string(),
        total_requests: 1200,
        successful_requests: 1188,
        sla_pct: 99.0,
        avg_latency_ms: 12.5,
        p50_latency_ms: 9,
        p95_latency_ms: 40,
        p99_latency_ms: 95,
        target_pct: 99.9,
        meets_target: true,
    }
}

fn sla_bucket() -> SlaBucketRow {
    SlaBucketRow {
        route_id: "route-1".to_string(),
        bucket_start: "2026-09-09T10:00:00Z".to_string(),
        request_count: 20,
        success_count: 19,
        error_count: 1,
        latency_sum_ms: 250,
        latency_min_ms: 3,
        latency_max_ms: 80,
        latency_p50_ms: 9,
        latency_p95_ms: 40,
        latency_p99_ms: 75,
        source: "passive".to_string(),
        cfg_max_latency_ms: 500,
        cfg_status_min: 200,
        cfg_status_max: 399,
        cfg_target_pct: 99.9,
    }
}

/// Every message the protocol carries, one instance each, every
/// scalar non-default so prost emits every field.
fn corpus() -> Vec<Entry> {
    vec![
        entry(
            "Hello",
            Hello {
                protocol_min: 1,
                protocol_max: 1,
                schema_version: 53,
                node_name: "edge-a".to_string(),
                build_version: "1.7.0".to_string(),
                applied_generation: 7,
                applied_hash: "sha256:ab12".to_string(),
                break_glass: true,
            },
        ),
        entry(
            "HelloAck",
            HelloAck {
                negotiated_version: 1,
                schema_version: 53,
                fleet_size_hint: 3,
                current_generation: 8,
                current_hash: "sha256:cd34".to_string(),
            },
        ),
        entry("NodeResources", resources()),
        entry("Heartbeat", heartbeat()),
        entry("HeartbeatAck", heartbeat_ack()),
        entry(
            "Enroll",
            Enroll {
                public_id: "tok-01".to_string(),
                secret: vec![0x11; 32],
                public_key_der: vec![0x30, 0x2a, 0x30, 0x05],
                node_name: "edge-a".to_string(),
                build_version: "1.7.0".to_string(),
                schema_version: 53,
            },
        ),
        entry(
            "EnrollAck",
            EnrollAck {
                node_id: "node-1".to_string(),
                cert_pem: pem("CERTIFICATE"),
                ca_pem: pem("CERTIFICATE"),
                status: "pending".to_string(),
                cert_not_after: "2026-12-08T00:00:00Z".to_string(),
            },
        ),
        entry(
            "Renew",
            Renew {
                public_key_der: vec![0x30, 0x2a, 0x30, 0x05],
            },
        ),
        entry(
            "RenewAck",
            RenewAck {
                cert_pem: pem("CERTIFICATE"),
                cert_not_after: "2027-03-08T00:00:00Z".to_string(),
            },
        ),
        entry("Leave", Leave {}),
        entry("LeaveAck", LeaveAck {}),
        entry(
            "ConfigPrepare",
            ConfigPrepare {
                generation: 8,
                hash: "sha256:cd34".to_string(),
                blob: vec![0xde, 0xad, 0xbe, 0xef],
            },
        ),
        entry(
            "ConfigPrepareAck",
            ConfigPrepareAck {
                accepted: true,
                reason: "a route names a backend this node cannot resolve".to_string(),
            },
        ),
        entry("ConfigCommit", ConfigCommit { generation: 8 }),
        entry(
            "ConfigCommitAck",
            ConfigCommitAck {
                applied_generation: 8,
                applied_hash: "sha256:cd34".to_string(),
            },
        ),
        entry("ConfigAbort", ConfigAbort { generation: 8 }),
        entry("ConfigAbortAck", ConfigAbortAck {}),
        entry(
            "ConfigPull",
            ConfigPull {
                applied_generation: 7,
                applied_hash: "sha256:ab12".to_string(),
            },
        ),
        entry(
            "ConfigPullAck",
            ConfigPullAck {
                generation: 8,
                hash: "sha256:cd34".to_string(),
                blob: vec![0xde, 0xad, 0xbe, 0xef],
                up_to_date: true,
            },
        ),
        entry("CertMaterial", cert_material()),
        entry(
            "CertPush",
            CertPush {
                bundles: vec![cert_material()],
            },
        ),
        entry(
            "CertRefusal",
            CertRefusal {
                cert_id: "cert-1".to_string(),
                reason: "digest mismatch".to_string(),
            },
        ),
        entry(
            "CertPushAck",
            CertPushAck {
                installed: vec!["cert-1".to_string()],
                refused: vec![CertRefusal {
                    cert_id: "cert-2".to_string(),
                    reason: "digest mismatch".to_string(),
                }],
            },
        ),
        entry(
            "CertPull",
            CertPull {
                cert_ids: vec!["cert-1".to_string(), "cert-2".to_string()],
            },
        ),
        entry(
            "CertPullAck",
            CertPullAck {
                bundles: vec![cert_material()],
            },
        ),
        entry("TelemetryAccessRow", access_row()),
        entry("TelemetryWafRow", waf_row()),
        entry("TelemetryBan", ban()),
        entry("TelemetryAuditRow", audit_row()),
        entry("TelemetryPush", telemetry_push()),
        entry(
            "TelemetryPushAck",
            TelemetryPushAck {
                accepted_access: 1,
                accepted_waf: 1,
                accepted_bans: 1,
                retry_after_s: 60,
                access_cursor: 1001,
                waf_cursor: 77,
                accepted_audit: 1,
                audit_cursor: 41,
            },
        ),
        entry(
            "BanPush",
            BanPush {
                client_ip: "192.0.2.10".to_string(),
                duration_s: 600,
                reason: "operator".to_string(),
            },
        ),
        entry("BanPushAck", BanPushAck { applied: true }),
        entry(
            "SlaPull",
            SlaPull {
                route_id: "route-1".to_string(),
                source: "passive".to_string(),
                from: "2026-09-09T09:00:00Z".to_string(),
                to: "2026-09-09T10:00:00Z".to_string(),
                buckets: true,
            },
        ),
        entry("SlaSummaryRow", sla_summary()),
        entry("SlaBucketRow", sla_bucket()),
        entry(
            "SlaPullAck",
            SlaPullAck {
                summaries: vec![sla_summary()],
                buckets: vec![sla_bucket()],
            },
        ),
        entry(
            "ChallengePublish",
            ChallengePublish {
                identifier: "fleet.example.com".to_string(),
                token: "tok".to_string(),
                key_authorization: "tok.thumb".to_string(),
            },
        ),
        entry("ChallengePublishAck", ChallengePublishAck {}),
        entry(
            "ChallengeRetract",
            ChallengeRetract {
                token: "tok".to_string(),
            },
        ),
        entry("ChallengeRetractAck", ChallengeRetractAck {}),
        entry(
            "ClusterRequest",
            ClusterRequest {
                sequence: 5,
                body_kind: 11,
                body: Some(cluster_request::Body::Heartbeat(heartbeat())),
            },
        ),
        entry(
            "ClusterResponse",
            ClusterResponse {
                sequence: 5,
                // `ClusterStatus::Ok`, as the wire carries it.
                status: 1,
                retry_after_s: 2,
                body: Some(cluster_response::Body::HeartbeatAck(heartbeat_ack())),
            },
        ),
        entry(
            "ClusterFrame",
            ClusterFrame {
                kind: Some(cluster_frame::Kind::Request(ClusterRequest {
                    sequence: 6,
                    body_kind: 40,
                    body: Some(cluster_request::Body::TelemetryPush(telemetry_push())),
                })),
            },
        ),
    ]
}

fn to_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".to_string();
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(text: &str) -> Result<Vec<u8>, String> {
    if text == "-" {
        return Ok(Vec::new());
    }
    if !text.len().is_multiple_of(2) {
        return Err("odd hex length".to_string());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn fixture() -> BTreeMap<String, Vec<u8>> {
    let text = std::fs::read_to_string(FIXTURE)
        .unwrap_or_else(|e| panic!("{FIXTURE} is missing ({e}); run the `regenerate` test"));
    let mut out = BTreeMap::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, hex) = line
            .split_once(' ')
            .unwrap_or_else(|| panic!("{FIXTURE}:{}: expected `<name> <hex>`", n + 1));
        let bytes = from_hex(hex.trim())
            .unwrap_or_else(|e| panic!("{FIXTURE}:{}: bad hex for {name}: {e}", n + 1));
        assert!(
            out.insert(name.to_string(), bytes).is_none(),
            "{FIXTURE}:{}: {name} appears twice",
            n + 1
        );
    }
    out
}

#[test]
fn every_message_encodes_to_its_frozen_bytes() {
    let frozen = fixture();
    let mut missing = Vec::new();
    let mut changed = Vec::new();
    for entry in corpus() {
        match frozen.get(entry.name) {
            None => missing.push(entry.name),
            Some(bytes) if *bytes != entry.encoded => changed.push(entry.name),
            Some(_) => {}
        }
    }
    assert!(
        missing.is_empty(),
        "no frozen encoding for {missing:?}: a new message needs a fixture line \
         (run the `regenerate` test)"
    );
    assert!(
        changed.is_empty(),
        "the encoding of {changed:?} differs from what v1.7.0 put on the wire; a peer one \
         release behind holds the frozen bytes, so decide whether this is compatible before \
         updating the fixture"
    );
}

#[test]
fn every_frozen_message_decodes_to_its_instance() {
    let frozen = fixture();
    let mut failed = Vec::new();
    for entry in corpus() {
        let Some(bytes) = frozen.get(entry.name) else {
            continue;
        };
        match (entry.round_trips)(bytes) {
            Ok(true) => {}
            Ok(false) => failed.push(format!("{}: decoded to a different value", entry.name)),
            Err(e) => failed.push(format!("{}: {e}", entry.name)),
        }
    }
    assert!(
        failed.is_empty(),
        "the bytes v1.7.0 puts on the wire no longer decode to what they meant: {failed:?}"
    );
}

#[test]
fn every_frozen_line_still_names_a_message() {
    // A fixture line nobody builds any more is a message that was
    // removed from the protocol, which is the incompatible change the
    // corpus exists to make visible.
    let frozen = fixture();
    let known: Vec<&str> = corpus().into_iter().map(|e| e.name).collect();
    let orphaned: Vec<&String> = frozen
        .keys()
        .filter(|name| {
            let base = name.split("-v").next().unwrap_or(name);
            !known.contains(&base)
        })
        .collect();
    assert!(
        orphaned.is_empty(),
        "{orphaned:?} are frozen but no longer built; a removed message is a wire change"
    );
}

/// Prints the fixture body. Ignored: it is a tool, not an assertion.
#[test]
#[ignore]
fn regenerate() {
    println!("# WIRE-CORPUS-BEGIN");
    println!("# v1.7.0 wire corpus, one line per message: <name> <hex or ->");
    println!("# Generated by `wire_corpus::regenerate`; see the test file's header.");
    for entry in corpus() {
        println!("{} {}", entry.name, to_hex(&entry.encoded));
    }
    println!("# WIRE-CORPUS-END");
}
