// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Per-subcommand CLI handlers for the `lorica` binary.
//!
//! Each submodule owns the body of one clap `Commands` variant (see
//! `main.rs`). The dispatch `match` in `main()` calls these helpers
//! with already-destructured arguments, so the handler bodies stay
//! free of the surrounding clap plumbing and stay testable in
//! isolation.

pub mod rotate_key;
pub mod unban;
