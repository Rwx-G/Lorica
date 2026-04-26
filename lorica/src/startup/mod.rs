// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Process boot helpers shared across the supervisor, worker, and
//! single-process roles.
//!
//! Each submodule owns one slice of the wiring that used to live inline
//! in `main.rs::run_supervisor` / `run_worker` / `run_single_process`.
//! Splitting them out lets every role spawn the same set of background
//! tasks through one entry point and prevents the v1.5.2-style asymmetry
//! where one role silently misses a spawn that landed in the others.

pub mod control_plane;
