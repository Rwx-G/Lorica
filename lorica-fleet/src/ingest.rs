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

//! What the control plane stores of one telemetry push (Story 9.6
//! AC #8, Story 9.9 AC #2).
//!
//! The decision, without the I/O around it: the listener's ingest
//! handler in the binary stores the audit rows, stats the fan-in
//! database, applies the ban snapshot, inserts the rows and counts what
//! was dropped; [`admit`] says how much of the batch that is.
//!
//! [`admit`] is deterministic given the state of the [`IngestQuota`] it
//! is handed, not pure: the quota charges what it allows in the same
//! lock as the decision, so two batches from one node cannot both be
//! told there is room for the same remaining budget.
//!
//! The rules, each with its test below:
//! - **Audit rows are charged but exempt.** They count against the
//!   node's quota, rows and bytes, and are never shed by its verdict.
//!   Losing an access row costs a line of traffic; losing an audit row
//!   costs the record of an operator action.
//! - **Measured before they are taken.** The quota is computed from
//!   what remains in the batch once the audit rows are out, so their
//!   charge is measured first; [`ChargedBatch::take_audit`] is the only
//!   way to a batch [`admit`] accepts, so the order cannot be inverted.
//! - **The storage watermark overrides every per-node budget.** When the
//!   fan-in database is at its cap, a node well inside its quota is shed
//!   too, ban snapshot included, and its quota is not charged.
//! - **Drop reasons** are the metric labels the handler counts under,
//!   [`DropReason::label`].

use lorica_cluster::{IngestQuota, IngestVerdict, TelemetryAuditRow, TelemetryPush};

/// What a batch's audit rows cost the node against its quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditCharge {
    /// Audit rows in the batch.
    pub rows: usize,
    /// What they will cost on disk, estimated as [`audit_bytes`] does.
    pub bytes: u64,
}

/// A telemetry push whose audit rows have been measured and taken out.
#[derive(Debug)]
pub struct ChargedBatch {
    batch: TelemetryPush,
    audit: AuditCharge,
}

impl ChargedBatch {
    /// Measure the batch's audit rows, then take them out, and return
    /// the rest of the batch with the charge alongside the rows.
    ///
    /// Measured BEFORE the take, because the quota is computed from what
    /// remains in the batch. Without the charge the node would pay
    /// nothing for audit rows, which is not what the proto comment and
    /// Story 9.9 say: they are counted against the quota and exempt from
    /// its VERDICT, which are different things. Charging them is what
    /// makes a node flooding audit get a `retry_after_s` even though its
    /// rows are stored.
    pub fn take_audit(mut batch: TelemetryPush) -> (Self, Vec<TelemetryAuditRow>) {
        let audit = AuditCharge {
            rows: batch.audit.len(),
            bytes: audit_bytes(&batch.audit),
        };
        let rows = std::mem::take(&mut batch.audit);
        (Self { batch, audit }, rows)
    }

    /// The batch without its audit rows.
    pub fn batch(&self) -> &TelemetryPush {
        &self.batch
    }

    /// What the audit rows taken out of it cost.
    pub fn audit_charge(&self) -> AuditCharge {
        self.audit
    }

    /// The batch without its audit rows, to store what [`admit`] allows.
    pub fn into_batch(self) -> TelemetryPush {
        self.batch
    }
}

/// What the handler measured before deciding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestStats {
    /// The fan-in database's size on disk, WAL included.
    pub storage_used_bytes: u64,
    /// The size at which telemetry is shed fleet-wide.
    pub storage_cap_bytes: u64,
}

/// Why telemetry rows were dropped, as the drop metric labels it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// The fan-in database is at its cap; every node is shed.
    StorageWatermark,
    /// This node is over its own ingest budget.
    NodeQuota,
}

impl DropReason {
    /// The `reason` label of the drop counter.
    pub fn label(self) -> &'static str {
        match self {
            Self::StorageWatermark => "storage_watermark",
            Self::NodeQuota => "node_quota",
        }
    }
}

/// How much of a batch the node may store, under its quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admission {
    /// Access rows to store, from the front of the batch.
    pub take_access: usize,
    /// WAF events to store, from the front of the batch.
    pub take_waf: usize,
    /// Access rows and WAF events the quota dropped.
    pub quota_dropped: u64,
    /// Whether the ban snapshot is applied. A node whose quota is
    /// exhausted does not get its snapshot applied, so ban spam cannot
    /// buy an unbounded amount of work under the store lock.
    pub apply_bans: bool,
    /// What the ack tells the node to wait, 0 for nothing.
    pub retry_after_s: u32,
}

/// What [`admit`] decided for one batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    /// The storage watermark shed the batch's telemetry, ban snapshot
    /// included. The quota was not consulted. The audit rows were
    /// already stored: the watermark sheds telemetry, never the trail.
    StorageShed {
        /// Access rows, WAF events and bans dropped.
        dropped: u64,
        /// What the ack tells the node to wait.
        retry_after_s: u32,
    },
    /// The node's quota decided.
    Admitted(Admission),
}

impl IngestOutcome {
    /// What to count in the drop metric, if anything. The watermark is
    /// always counted, even at zero rows, so its series exists the
    /// moment it fires; a quota drop only when rows were dropped.
    pub fn dropped(&self) -> Option<(DropReason, u64)> {
        match self {
            Self::StorageShed { dropped, .. } => Some((DropReason::StorageWatermark, *dropped)),
            Self::Admitted(admission) if admission.quota_dropped > 0 => {
                Some((DropReason::NodeQuota, admission.quota_dropped))
            }
            Self::Admitted(_) => None,
        }
    }
}

/// Decide how much of `batch` `node_id` may store, and charge the
/// node's quota for it. See the module documentation for the rules.
pub fn admit(
    batch: &ChargedBatch,
    node_id: &str,
    stats: &IngestStats,
    quota: &IngestQuota,
) -> IngestOutcome {
    let push = &batch.batch;
    let storage =
        lorica_cluster::storage_verdict(stats.storage_used_bytes, stats.storage_cap_bytes);
    if matches!(storage, IngestVerdict::Shed { .. }) {
        return IngestOutcome::StorageShed {
            dropped: (push.access.len() + push.waf.len() + push.bans.len()) as u64,
            retry_after_s: storage.retry_after_s(),
        };
    }

    let bytes = estimated_bytes(push) + batch.audit.bytes;
    // Bans are part of what the node offered, so they are part of what
    // it is charged for, and so are the audit rows already stored.
    let verdict = quota.admit(
        node_id,
        push.access.len(),
        push.waf.len() + push.bans.len() + batch.audit.rows,
        bytes,
    );
    let take_access = verdict.access_allowance(push.access.len());
    let take_waf = verdict.waf_allowance(push.waf.len());
    IngestOutcome::Admitted(Admission {
        take_access,
        take_waf,
        quota_dropped: ((push.access.len() - take_access) + (push.waf.len() - take_waf)) as u64,
        apply_bans: !matches!(verdict, IngestVerdict::Shed { .. }),
        retry_after_s: verdict.retry_after_s(),
    })
}

/// What a batch's audit rows will cost on disk (Story 9.9).
///
/// Separate from [`estimated_bytes`] because the audit rows are taken
/// out of the batch before the quota is computed: they are exempt from
/// the shedding verdict, not from the accounting, and a node that
/// pushes only audit rows must still be charged for the work.
pub fn audit_bytes(rows: &[TelemetryAuditRow]) -> u64 {
    const ROW_OVERHEAD: u64 = 64;
    rows.iter()
        .map(|r| {
            ROW_OVERHEAD
                + (r.timestamp.len()
                    + r.operator_username.len()
                    + r.operator_role.len()
                    + r.action.len()
                    + r.target_type.len()
                    + r.target_id.len()
                    + r.before_payload_hash.len()
                    + r.after_payload_hash.len()
                    + r.ip.len()
                    + r.user_agent.len()
                    + r.prev_chain_hash.len()
                    + r.chain_hash.len()) as u64
        })
        .sum()
}

/// Roughly what a batch will cost on disk, for the byte side of the
/// ingest quota (Story 9.6 AC #8).
///
/// Estimated from the decoded payload rather than measured from the
/// frame: the frame is gone by the time this runs, and what the quota
/// is protecting is disk, not bandwidth. The fixed addend per row
/// stands in for the row overhead SQLite adds on top of the strings.
pub fn estimated_bytes(batch: &TelemetryPush) -> u64 {
    const ROW_OVERHEAD: u64 = 64;
    // Bans are counted too. They replace rather than append, so they
    // cannot grow the database without bound, but each snapshot is a
    // DELETE plus up to 256 INSERTs under the store lock: the WORK is
    // unbounded even where the storage is not, and a node sending
    // only bans would otherwise pay nothing for it.
    let bans: u64 = batch
        .bans
        .iter()
        .map(|b| ROW_OVERHEAD + (b.client_ip.len() + b.reason.len()) as u64)
        .sum();
    let access: u64 = batch
        .access
        .iter()
        .map(|r| {
            ROW_OVERHEAD
                + (r.timestamp.len()
                    + r.method.len()
                    + r.path.len()
                    + r.host.len()
                    + r.backend.len()
                    + r.error.len()
                    + r.client_ip.len()
                    + r.xff_proxy_ip.len()
                    + r.source.len()
                    + r.request_id.len()) as u64
        })
        .sum();
    let waf: u64 = batch
        .waf
        .iter()
        .map(|r| {
            ROW_OVERHEAD
                + (r.description.len()
                    + r.category.len()
                    + r.matched_field.len()
                    + r.matched_value.len()
                    + r.timestamp.len()
                    + r.client_ip.len()
                    + r.route_hostname.len()
                    + r.action.len()) as u64
        })
        .sum();
    access + waf + bans
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use lorica_cluster::{TelemetryAccessRow, TelemetryBan, TelemetryWafRow, QUOTA_RETRY_AFTER_S};

    use super::*;

    const NODE: &str = "node-a";
    const ROOMY: IngestStats = IngestStats {
        storage_used_bytes: 0,
        storage_cap_bytes: 1024,
    };
    const FULL: IngestStats = IngestStats {
        storage_used_bytes: 1024,
        storage_cap_bytes: 1024,
    };

    fn quota(rows: u64) -> IngestQuota {
        IngestQuota::with_budget(rows, u64::MAX, Duration::from_secs(3600))
    }

    fn push(access: usize, waf: usize, bans: usize, audit: usize) -> TelemetryPush {
        TelemetryPush {
            access: (0..access)
                .map(|i| TelemetryAccessRow {
                    path: format!("/{i}"),
                    ..Default::default()
                })
                .collect(),
            waf: (0..waf)
                .map(|_| TelemetryWafRow {
                    category: "sqli".into(),
                    ..Default::default()
                })
                .collect(),
            bans: (0..bans)
                .map(|i| TelemetryBan {
                    client_ip: format!("192.0.2.{i}"),
                    ..Default::default()
                })
                .collect(),
            audit: (0..audit)
                .map(|i| TelemetryAuditRow {
                    origin_id: i as u64 + 1,
                    action: "route.update".into(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    fn admitted(outcome: IngestOutcome) -> Admission {
        match outcome {
            IngestOutcome::Admitted(admission) => admission,
            other => panic!("expected the quota to decide, got {other:?}"),
        }
    }

    #[test]
    fn the_audit_charge_is_measured_before_the_rows_are_taken() {
        let offered = push(1, 0, 0, 3);
        let expected = AuditCharge {
            rows: 3,
            bytes: audit_bytes(&offered.audit),
        };
        assert!(expected.bytes > 0);
        let (charged, rows) = ChargedBatch::take_audit(offered);
        assert_eq!(rows.len(), 3, "the rows go to the audit log");
        assert!(charged.batch().audit.is_empty(), "and out of the batch");
        assert_eq!(
            charged.audit_charge(),
            expected,
            "measured on the rows, not on the emptied batch"
        );
    }

    #[test]
    fn audit_rows_are_charged_against_the_quota() {
        let quota = quota(2);
        let (audit_only, _) = ChargedBatch::take_audit(push(0, 0, 0, 2));
        let first = admitted(admit(&audit_only, NODE, &ROOMY, &quota));
        assert_eq!(first.retry_after_s, 0, "inside the budget");

        let (next, _) = ChargedBatch::take_audit(push(1, 0, 0, 0));
        let second = admitted(admit(&next, NODE, &ROOMY, &quota));
        assert_eq!(
            second.take_access, 0,
            "the audit rows spent the budget: a node that pushed only audit paid for them"
        );
        assert_eq!(second.retry_after_s, QUOTA_RETRY_AFTER_S);
    }

    #[test]
    fn audit_rows_are_exempt_from_the_verdict() {
        let quota = quota(1);
        let (spend, _) = ChargedBatch::take_audit(push(1, 0, 0, 0));
        admitted(admit(&spend, NODE, &ROOMY, &quota));

        let (over, rows) = ChargedBatch::take_audit(push(2, 1, 0, 4));
        let outcome = admit(&over, NODE, &ROOMY, &quota);
        assert_eq!(
            rows.len(),
            4,
            "every audit row is stored, over quota or not"
        );
        assert_eq!(
            outcome.dropped(),
            Some((DropReason::NodeQuota, 3)),
            "only access rows and WAF events are ever dropped"
        );
    }

    #[test]
    fn the_storage_watermark_overrides_the_node_quota_and_charges_nothing() {
        let quota = quota(6);
        let (batch, rows) = ChargedBatch::take_audit(push(2, 1, 3, 1));
        let outcome = admit(&batch, NODE, &FULL, &quota);
        assert_eq!(
            outcome,
            IngestOutcome::StorageShed {
                dropped: 6,
                retry_after_s: QUOTA_RETRY_AFTER_S,
            },
            "a node well inside its quota is shed, ban snapshot included"
        );
        assert_eq!(rows.len(), 1, "the trail is never shed");
        assert_eq!(outcome.dropped(), Some((DropReason::StorageWatermark, 6)));

        let (same, _) = ChargedBatch::take_audit(push(2, 1, 3, 0));
        let after = admitted(admit(&same, NODE, &ROOMY, &quota));
        assert_eq!(
            (after.take_access, after.take_waf, after.retry_after_s),
            (2, 1, 0),
            "the shed batch spent none of the node's budget"
        );
    }

    #[test]
    fn the_watermark_is_counted_even_when_it_drops_nothing() {
        let (empty, _) = ChargedBatch::take_audit(push(0, 0, 0, 2));
        assert_eq!(
            admit(&empty, NODE, &FULL, &quota(10)).dropped(),
            Some((DropReason::StorageWatermark, 0))
        );
    }

    #[test]
    fn under_the_watermark_and_inside_the_quota_everything_is_stored() {
        let (batch, _) = ChargedBatch::take_audit(push(3, 2, 1, 1));
        let outcome = admit(&batch, NODE, &ROOMY, &quota(100));
        assert_eq!(
            admitted(outcome),
            Admission {
                take_access: 3,
                take_waf: 2,
                quota_dropped: 0,
                apply_bans: true,
                retry_after_s: 0,
            }
        );
        assert_eq!(outcome.dropped(), None);
    }

    #[test]
    fn a_node_over_its_quota_keeps_part_of_the_batch_and_its_bans() {
        let (batch, _) = ChargedBatch::take_audit(push(4, 2, 0, 0));
        let outcome = admit(&batch, NODE, &ROOMY, &quota(3));
        let admission = admitted(outcome);
        assert_eq!(admission.take_access + admission.take_waf, 3);
        assert_eq!(admission.quota_dropped, 3);
        assert!(admission.apply_bans, "a partial verdict still applies bans");
        assert_eq!(admission.retry_after_s, QUOTA_RETRY_AFTER_S);
        assert_eq!(outcome.dropped(), Some((DropReason::NodeQuota, 3)));
    }

    #[test]
    fn a_node_whose_quota_is_spent_gets_no_ban_snapshot_applied() {
        let quota = quota(2);
        let (bans_only, _) = ChargedBatch::take_audit(push(0, 0, 3, 0));
        assert!(
            admitted(admit(&bans_only, NODE, &ROOMY, &quota)).apply_bans,
            "bans fit partly, and are charged"
        );
        let (more, _) = ChargedBatch::take_audit(push(1, 0, 2, 0));
        let admission = admitted(admit(&more, NODE, &ROOMY, &quota));
        assert!(
            !admission.apply_bans,
            "the bans spent the budget, so the next snapshot is not applied"
        );
        assert_eq!(admission.take_access, 0);
    }

    #[test]
    fn the_drop_reasons_are_the_metric_labels() {
        assert_eq!(DropReason::StorageWatermark.label(), "storage_watermark");
        assert_eq!(DropReason::NodeQuota.label(), "node_quota");
    }
}
