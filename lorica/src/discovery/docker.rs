// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Docker Swarm service discovery via the Docker socket API.
//!
//! Connects to the Docker daemon (default: unix socket) and lists tasks
//! for a given service. Each running task with a network endpoint becomes
//! a discovered backend.

use bollard::Docker;
use bollard::service::TaskState;
use tracing::{debug, warn};

use super::{DiscoveredEndpoint, DiscoveryError};

/// Docker Swarm service discovery client.
pub struct DockerDiscovery {
    client: Docker,
}

impl DockerDiscovery {
    /// Connect to the Docker daemon using the default socket.
    pub fn connect() -> Result<Self, DiscoveryError> {
        let client = Docker::connect_with_socket_defaults()
            .map_err(|e| DiscoveryError::Docker(format!("failed to connect: {e}")))?;
        Ok(Self { client })
    }

    /// Connect to the Docker daemon at a specific URL.
    pub fn connect_with_url(url: &str) -> Result<Self, DiscoveryError> {
        let client = Docker::connect_with_http(url, 5, bollard::API_DEFAULT_VERSION)
            .map_err(|e| DiscoveryError::Docker(format!("failed to connect to {url}: {e}")))?;
        Ok(Self { client })
    }

    /// Discover endpoints for a Docker Swarm service by name or ID.
    ///
    /// Returns one endpoint per running task with a network attachment.
    pub async fn discover_service(
        &self,
        service_name: &str,
        target_port: u16,
    ) -> Result<Vec<DiscoveredEndpoint>, DiscoveryError> {
        use bollard::service::TaskSpec;
        use std::collections::HashMap;

        // List tasks for the service
        let mut filters = HashMap::new();
        filters.insert("service", vec![service_name]);
        filters.insert("desired-state", vec!["running"]);

        let tasks = self
            .client
            .list_tasks(Some(bollard::task::ListTasksOptions {
                filters,
            }))
            .await
            .map_err(|e| DiscoveryError::Docker(format!("failed to list tasks: {e}")))?;

        let mut endpoints = Vec::new();

        for task in &tasks {
            let task_id = task.id.as_deref().unwrap_or("unknown");
            let node_id = task.node_id.as_deref().unwrap_or("unknown");

            // Check task state
            let state = task
                .status
                .as_ref()
                .and_then(|s| s.state.as_ref())
                .cloned();

            let healthy = state == Some(TaskState::RUNNING);

            // Get the task's network attachment IP
            let ip = task
                .network_attachments
                .as_ref()
                .and_then(|attachments| {
                    attachments.iter().find_map(|a| {
                        a.addresses.as_ref().and_then(|addrs| {
                            addrs.first().map(|addr| {
                                // Addresses are in CIDR format (e.g. "10.0.0.5/24")
                                addr.split('/').next().unwrap_or(addr).to_string()
                            })
                        })
                    })
                });

            if let Some(ip) = ip {
                let address = format!("{ip}:{target_port}");
                debug!(
                    service = service_name,
                    task_id = task_id,
                    node = node_id,
                    address = %address,
                    healthy = healthy,
                    "discovered Docker Swarm endpoint"
                );

                let mut labels = std::collections::HashMap::new();
                labels.insert("task_id".to_string(), task_id.to_string());
                labels.insert("node_id".to_string(), node_id.to_string());
                labels.insert("source".to_string(), "docker_swarm".to_string());

                endpoints.push(DiscoveredEndpoint {
                    address,
                    healthy,
                    labels,
                });
            } else {
                warn!(
                    service = service_name,
                    task_id = task_id,
                    "Docker Swarm task has no network attachment IP"
                );
            }
        }

        debug!(
            service = service_name,
            count = endpoints.len(),
            "Docker Swarm service discovery complete"
        );

        Ok(endpoints)
    }

    /// Ping the Docker daemon to verify connectivity.
    pub async fn ping(&self) -> Result<(), DiscoveryError> {
        self.client
            .ping()
            .await
            .map_err(|e| DiscoveryError::Docker(format!("ping failed: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovered_endpoint_equality() {
        let a = DiscoveredEndpoint {
            address: "10.0.0.1:8080".into(),
            healthy: true,
            labels: std::collections::HashMap::new(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_discovered_endpoint_with_labels() {
        let mut labels = std::collections::HashMap::new();
        labels.insert("task_id".to_string(), "abc123".to_string());
        let ep = DiscoveredEndpoint {
            address: "10.0.0.2:80".into(),
            healthy: false,
            labels,
        };
        assert_eq!(ep.labels.get("task_id").unwrap(), "abc123");
        assert!(!ep.healthy);
    }

    // Integration tests require a running Docker daemon - skip in CI
    #[tokio::test]
    async fn test_connect_fails_gracefully_without_docker() {
        // Connect with a bogus URL should fail
        let result = DockerDiscovery::connect_with_url("http://192.0.2.1:1");
        // bollard may succeed at creation but fail at use, or fail immediately
        // Either way, we verify no panic
        match result {
            Ok(d) => {
                let ping = d.ping().await;
                assert!(ping.is_err());
            }
            Err(_) => {} // Expected without Docker
        }
    }
}
