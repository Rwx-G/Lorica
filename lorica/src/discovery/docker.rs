// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Docker Swarm service discovery via the Docker socket API.
//!
//! Connects to the Docker daemon and lists services with their
//! virtual IPs. Each Swarm service with an exposed endpoint
//! becomes a discovered backend.

use bollard::service::ListServicesOptions;
use bollard::Docker;
use std::collections::HashMap;
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

    /// Connect to the Docker daemon at a specific HTTP URL.
    pub fn connect_with_url(url: &str) -> Result<Self, DiscoveryError> {
        let client = Docker::connect_with_http(url, 5, bollard::API_DEFAULT_VERSION)
            .map_err(|e| DiscoveryError::Docker(format!("failed to connect to {url}: {e}")))?;
        Ok(Self { client })
    }

    /// Discover endpoints for a Docker Swarm service by name.
    ///
    /// Uses the service's virtual IPs from its endpoint spec.
    /// Each VIP on the ingress or custom overlay network is returned.
    pub async fn discover_service(
        &self,
        service_name: &str,
        target_port: u16,
    ) -> Result<Vec<DiscoveredEndpoint>, DiscoveryError> {
        let mut filters = HashMap::new();
        filters.insert("name", vec![service_name]);

        let services = self
            .client
            .list_services(Some(ListServicesOptions {
                filters,
                status: true,
            }))
            .await
            .map_err(|e| DiscoveryError::Docker(format!("failed to list services: {e}")))?;

        let mut endpoints = Vec::new();

        for svc in &services {
            let svc_id = svc.id.as_deref().unwrap_or("unknown");
            let svc_name = svc
                .spec
                .as_ref()
                .and_then(|s| s.name.as_deref())
                .unwrap_or(service_name);

            // Derive health from running vs desired task counts.
            // A service with zero running tasks is unhealthy even if it has a VIP.
            let (running, desired) = svc
                .service_status
                .as_ref()
                .map(|s| {
                    (
                        s.running_tasks.unwrap_or(0),
                        s.desired_tasks.unwrap_or(0),
                    )
                })
                .unwrap_or((0, 0));

            let healthy = running > 0 && running >= desired;

            if running == 0 && desired > 0 {
                warn!(
                    service = svc_name,
                    desired = desired,
                    "Docker Swarm service has zero running tasks - marking unhealthy"
                );
            }

            // Extract virtual IPs from endpoint
            if let Some(ref endpoint) = svc.endpoint {
                if let Some(ref vips) = endpoint.virtual_ips {
                    for vip in vips {
                        if let Some(ref addr) = vip.addr {
                            // VIP addresses are in CIDR format (e.g. "10.0.0.5/24")
                            let ip = addr.split('/').next().unwrap_or(addr);
                            let address = format!("{ip}:{target_port}");

                            let mut labels = HashMap::new();
                            labels.insert("source".to_string(), "docker_swarm".to_string());
                            labels.insert("service_id".to_string(), svc_id.to_string());
                            labels.insert("service_name".to_string(), svc_name.to_string());
                            labels.insert("running_tasks".to_string(), running.to_string());
                            labels.insert("desired_tasks".to_string(), desired.to_string());
                            if let Some(ref net_id) = vip.network_id {
                                labels.insert("network_id".to_string(), net_id.clone());
                            }

                            debug!(
                                service = svc_name,
                                address = %address,
                                running = running,
                                desired = desired,
                                healthy = healthy,
                                "discovered Docker Swarm service VIP"
                            );

                            endpoints.push(DiscoveredEndpoint {
                                address,
                                healthy,
                                labels,
                            });
                        }
                    }
                }

                // Also check published ports
                if let Some(ref ports) = endpoint.ports {
                    for port in ports {
                        if let (Some(published), Some(target)) =
                            (port.published_port, port.target_port)
                        {
                            if target as u16 == target_port {
                                debug!(
                                    service = svc_name,
                                    published = published,
                                    target = target,
                                    "discovered Docker Swarm published port"
                                );
                            }
                        }
                    }
                }
            } else {
                warn!(
                    service = svc_name,
                    "Docker Swarm service has no endpoint"
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
            labels: HashMap::new(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_discovered_endpoint_with_labels() {
        let mut labels = HashMap::new();
        labels.insert("service_id".to_string(), "abc123".to_string());
        let ep = DiscoveredEndpoint {
            address: "10.0.0.2:80".into(),
            healthy: false,
            labels,
        };
        assert_eq!(ep.labels.get("service_id").unwrap(), "abc123");
        assert!(!ep.healthy);
    }

    #[tokio::test]
    async fn test_connect_fails_gracefully_without_docker() {
        let result = DockerDiscovery::connect_with_url("http://192.0.2.1:1");
        match result {
            Ok(d) => {
                let ping = d.ping().await;
                assert!(ping.is_err());
            }
            Err(_) => {}
        }
    }
}
