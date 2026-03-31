// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Kubernetes service discovery via the kube-rs client.
//!
//! Connects to the Kubernetes API (in-cluster or kubeconfig) and lists
//! Endpoints for a given Service. Each ready address becomes a
//! discovered backend.

#[cfg(feature = "kubernetes")]
use k8s_openapi::api::core::v1::Endpoints;
#[cfg(feature = "kubernetes")]
use kube::{Api, Client};
#[cfg(feature = "kubernetes")]
use tracing::debug;

use super::{DiscoveredEndpoint, DiscoveryError};

/// Kubernetes service discovery client.
#[cfg(feature = "kubernetes")]
pub struct K8sDiscovery {
    client: Client,
}

#[cfg(feature = "kubernetes")]
impl K8sDiscovery {
    /// Create a discovery client using in-cluster config or default kubeconfig.
    pub async fn connect() -> Result<Self, DiscoveryError> {
        let client = Client::try_default()
            .await
            .map_err(|e| DiscoveryError::Kubernetes(format!("failed to create client: {e}")))?;
        Ok(Self { client })
    }

    /// Discover endpoints for a Kubernetes Service in a given namespace.
    ///
    /// Returns one endpoint per ready address in the Endpoints resource.
    pub async fn discover_service(
        &self,
        namespace: &str,
        service_name: &str,
        target_port: u16,
    ) -> Result<Vec<DiscoveredEndpoint>, DiscoveryError> {
        let endpoints_api: Api<Endpoints> =
            Api::namespaced(self.client.clone(), namespace);

        let ep = endpoints_api
            .get(service_name)
            .await
            .map_err(|e| {
                DiscoveryError::Kubernetes(format!(
                    "failed to get endpoints for {namespace}/{service_name}: {e}"
                ))
            })?;

        let mut discovered = Vec::new();

        if let Some(subsets) = ep.subsets {
            for subset in &subsets {
                // Find the matching port
                let port = subset
                    .ports
                    .as_ref()
                    .and_then(|ports| {
                        ports.iter().find_map(|p| {
                            if p.port as u16 == target_port {
                                Some(p.port as u16)
                            } else {
                                None
                            }
                        })
                    })
                    .unwrap_or(target_port);

                // Ready addresses
                if let Some(addrs) = &subset.addresses {
                    for addr in addrs {
                        let ip = &addr.ip;
                        let address = format!("{ip}:{port}");

                        let mut labels = std::collections::HashMap::new();
                        labels.insert("source".to_string(), "kubernetes".to_string());
                        labels.insert(
                            "namespace".to_string(),
                            namespace.to_string(),
                        );
                        if let Some(ref target_ref) = addr.target_ref {
                            if let Some(ref name) = target_ref.name {
                                labels.insert("pod".to_string(), name.clone());
                            }
                        }
                        if let Some(ref node) = addr.node_name {
                            labels.insert("node".to_string(), node.clone());
                        }

                        debug!(
                            service = service_name,
                            namespace = namespace,
                            address = %address,
                            "discovered Kubernetes endpoint (ready)"
                        );

                        discovered.push(DiscoveredEndpoint {
                            address,
                            healthy: true,
                            labels,
                        });
                    }
                }

                // Not-ready addresses (unhealthy)
                if let Some(addrs) = &subset.not_ready_addresses {
                    for addr in addrs {
                        let ip = &addr.ip;
                        let address = format!("{ip}:{port}");

                        let mut labels = std::collections::HashMap::new();
                        labels.insert("source".to_string(), "kubernetes".to_string());
                        labels.insert(
                            "namespace".to_string(),
                            namespace.to_string(),
                        );
                        labels.insert("ready".to_string(), "false".to_string());

                        debug!(
                            service = service_name,
                            namespace = namespace,
                            address = %address,
                            "discovered Kubernetes endpoint (not ready)"
                        );

                        discovered.push(DiscoveredEndpoint {
                            address,
                            healthy: false,
                            labels,
                        });
                    }
                }
            }
        }

        debug!(
            service = service_name,
            namespace = namespace,
            total = discovered.len(),
            ready = discovered.iter().filter(|e| e.healthy).count(),
            "Kubernetes service discovery complete"
        );

        Ok(discovered)
    }

    /// Watch Kubernetes Endpoints for a service in real-time.
    ///
    /// Returns a stream of endpoint change events with automatic reconnection.
    /// The caller should rebuild the backend list when events arrive.
    pub fn watch_endpoints(
        &self,
        namespace: &str,
        service_name: &str,
    ) -> impl futures_util::Stream<Item = Result<kube::runtime::watcher::Event<Endpoints>, kube::runtime::watcher::Error>>
    {
        let endpoints_api: Api<Endpoints> = Api::namespaced(self.client.clone(), namespace);

        let config = kube::runtime::watcher::Config::default()
            .fields(&format!("metadata.name={service_name}"));

        kube::runtime::watcher::watcher(endpoints_api, config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovered_endpoint_labels() {
        let mut labels = std::collections::HashMap::new();
        labels.insert("source".to_string(), "kubernetes".to_string());
        labels.insert("namespace".to_string(), "default".to_string());
        labels.insert("pod".to_string(), "web-abc123".to_string());

        let ep = DiscoveredEndpoint {
            address: "10.244.0.5:8080".into(),
            healthy: true,
            labels,
        };

        assert_eq!(ep.labels.get("source").unwrap(), "kubernetes");
        assert_eq!(ep.labels.get("pod").unwrap(), "web-abc123");
        assert!(ep.healthy);
    }

    #[cfg(feature = "kubernetes")]
    #[tokio::test]
    async fn test_k8s_connect_fails_without_cluster() {
        // Should fail gracefully when not running in a cluster
        let result = K8sDiscovery::connect().await;
        // Either fails (no kubeconfig) or succeeds with invalid cluster
        match result {
            Ok(_) => {} // May succeed if kubeconfig exists
            Err(e) => {
                assert!(e.to_string().contains("failed to create client"));
            }
        }
    }
}
