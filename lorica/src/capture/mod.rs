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

//! Traffic capture (Story 10.1).
//!
//! Five pieces: the compiled predicates a request is measured against
//! ([`rules`]), the per-request buffers a matched request fills
//! ([`buffers`]), the node-wide ceiling those buffers reserve from
//! ([`budget`]), the per-rule total and rate an emission is counted
//! against ([`budgets`]), and the task that disarms a rule which spent
//! its total ([`self_disable`]).
//!
//! `lorica-config` owns the stored shape of a capture rule; this module
//! owns the matcher built from it. The split follows where the `regex`
//! dependency lives: the config crate deliberately has none, so it caps
//! the source length of an operator pattern and this crate applies the
//! compile-time budget and holds the compiled automaton.

mod budget;
mod budgets;
mod buffers;
mod rules;
mod self_disable;

pub use budget::{node_budget, CaptureBudget, CaptureReservation, CAPTURE_MAX_INFLIGHT_BYTES};
pub use budgets::{
    node_budgets, CaptureAdmission, CaptureBudgets, PendingDisable, CAPTURE_MAX_TRACKED_RULES,
};
pub use buffers::{CaptureBody, CaptureSkip, CaptureState};
pub use rules::{CompiledCaptureRule, CompiledCaptureRules, CAPTURE_REGEX_SIZE_LIMIT};
pub use self_disable::{
    spawn_capture_disable_task, CAPTURE_AUTO_DISABLED_ACTION, CAPTURE_DISABLE_INTERVAL,
};
