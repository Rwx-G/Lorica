// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Service discovery modules for automatic backend management.

#[cfg(feature = "docker")]
pub mod docker;
pub mod kubernetes;

use serde::{Deserialize, Serialize};

/// A discovered backend endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredEndpoint {
    /// The address in "host:port" format.
    pub address: String,
    /// Whether this endpoint is healthy according to the discovery source.
    pub healthy: bool,
    /// Optional metadata (e.g. node ID, task ID).
    pub labels: std::collections::HashMap<String, String>,
}

/// Errors from service discovery.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("docker: {0}")]
    Docker(String),
    #[error("kubernetes: {0}")]
    Kubernetes(String),
    #[error("connection: {0}")]
    Connection(String),
}
