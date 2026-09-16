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

//! Traffic capture (Stories 10.1 and 10.2).
//!
//! Eight pieces: the compiled predicates a request is measured against
//! ([`rules`]), the per-request buffers a matched request fills
//! ([`buffers`]), the node-wide ceiling those buffers reserve from
//! ([`budget`]), the per-rule total and rate an emission is counted
//! against ([`budgets`]), the task that publishes the counters and
//! disarms a rule which spent its total ([`self_disable`]), the record
//! an admitted exchange becomes ([`record`]), the redaction applied to
//! it before it leaves the proxy ([`redact`]), and the outputs it
//! leaves through ([`sink`]).
//!
//! `lorica-config` owns the stored shape of a capture rule; this module
//! owns the matcher built from it. The split follows where the `regex`
//! dependency lives: the config crate deliberately has none, so it caps
//! the source length of an operator pattern and this crate applies the
//! compile-time budget and holds the compiled automaton.

mod budget;
mod budgets;
mod buffers;
mod record;
mod redact;
mod rules;
mod self_disable;
mod sink;

pub use budget::{node_budget, CaptureBudget, CaptureReservation, CAPTURE_MAX_INFLIGHT_BYTES};
pub use budgets::{
    node_budgets, CaptureAdmission, CaptureBudgets, PendingCounters, PendingDisable,
    CAPTURE_MAX_TRACKED_RULES,
};
pub use buffers::{CaptureBody, CaptureSkip, CaptureState};
pub use record::{
    is_textual_content_type, BodyEncoding, BodySkip, CaptureRecord, CapturedRequest,
    CapturedResponse, CAPTURE_RECORD_KIND,
};
pub use redact::{is_redacted_header, mask_query, redacted_marker, ALWAYS_REDACTED_HEADERS};
pub use rules::{CompiledCaptureRule, CompiledCaptureRules, CAPTURE_REGEX_SIZE_LIMIT};
pub use self_disable::{
    disable_expired, spawn_capture_disable_task, CAPTURE_AUTO_DISABLED_ACTION,
    CAPTURE_DISABLE_INTERVAL, CAPTURE_EXPIRED_BUDGET,
};
pub use sink::{
    capture_file_name, emit_captures, is_capture_file_name, prune_capture_dir, write_capture_file,
    CaptureDirWriter, CaptureEmission, CAPTURE_DIR_QUEUE_CAP, CAPTURE_DIR_QUEUE_MAX_BYTES,
    CAPTURE_DROPPED_SINK_OUTCOME, CAPTURE_FILE_MODE, CAPTURE_PRUNE_MAX_REMOVALS,
    CAPTURE_TRACING_TARGET,
};
