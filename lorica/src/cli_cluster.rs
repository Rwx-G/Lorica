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

//! `lorica cluster join | leave | status | token` (Story 9.3
//! AC #6/#13/#14, and the token CLI the dashboard-less operator
//! needs).
//!
//! `join` and the credential-less `leave` work on the node's database
//! directly (the service is normally stopped, or restarts afterwards);
//! `status` reads the database and, with credentials, the running
//! instance; `token` and the credential-backed `leave` go through the
//! local management API exactly like `lorica unban` does.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use lorica_cluster::{
    client_config, display_field_is_valid, join, split_host_port, token, HandshakeConfig,
    HandshakeError, JoinParams,
};
use lorica_config::models::ClusterIdentity;
use lorica_config::store::ConfigStore;
use lorica_cluster::tokio_rustls::rustls::pki_types::ServerName;
use lorica_cluster::tokio_rustls::TlsConnector;

/// Bound on one enrollment exchange.
const JOIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound on the deregistration probe of a credential-less `leave`.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

fn fail(message: impl std::fmt::Display) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

/// Open the node's configuration database the way the service does.
fn open_store(data_dir: &Path) -> ConfigStore {
    let key = lorica_config::crypto::EncryptionKey::load_or_create(&data_dir.join("encryption.key"))
        .unwrap_or_else(|e| fail(format!("failed to load the encryption key: {e}")));
    ConfigStore::open(&data_dir.join("lorica.db"), Some(key))
        .unwrap_or_else(|e| fail(format!("failed to open the configuration database: {e}")))
}

/// The join token from the documented paths (AC #6): `--token-file`,
/// then `--token-stdin`, then `LORICA_JOIN_TOKEN`. Never from argv.
fn read_join_token(token_file: Option<&Path>, token_stdin: bool) -> Result<String, String> {
    if let Some(path) = token_file {
        return std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read the token file {}: {e}", path.display()));
    }
    if token_stdin {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .map_err(|e| format!("cannot read the token from standard input: {e}"))?;
        return Ok(buffer);
    }
    if let Ok(from_env) = std::env::var("LORICA_JOIN_TOKEN") {
        if !from_env.trim().is_empty() {
            return Ok(from_env);
        }
    }
    Err("no join token: pass --token-file <path>, --token-stdin, or set LORICA_JOIN_TOKEN. \
         A token is never accepted on the command line (argv is readable through /proc and \
         lands in shell history and CI logs)."
        .to_string())
}

/// This machine's hostname without a libc binding.
fn local_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "node".to_string())
}

/// `host:port` with an IPv6 literal bracketed.
fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// `lorica cluster join`.
pub fn run_cluster_join(
    data_dir: &str,
    control_plane: String,
    enrollment: Option<String>,
    name: Option<String>,
    token_file: Option<PathBuf>,
    token_stdin: bool,
    server_name: Option<String>,
) {
    let raw = read_join_token(token_file.as_deref(), token_stdin).unwrap_or_else(|e| fail(e));
    let parsed = token::parse(&raw).unwrap_or_else(|_| fail("malformed join token"));
    let (host, port) = split_host_port(&control_plane).unwrap_or_else(|e| fail(e));
    let enrollment_addr = match enrollment {
        Some(explicit) => explicit,
        None => {
            let next = port
                .checked_add(1)
                .unwrap_or_else(|| fail("the control-plane port has no next port; pass --enrollment"));
            join_host_port(host, next)
        }
    };
    let expected_host = server_name.unwrap_or_else(|| host.to_string());
    let node_name = name.unwrap_or_else(local_hostname);
    if node_name.is_empty() || !display_field_is_valid(&node_name) {
        fail("the node name must be 1-64 bytes without control characters");
    }

    let data_dir = PathBuf::from(data_dir);
    let store = open_store(&data_dir);
    match store.get_cluster_ca() {
        Ok(Some(_)) => fail(
            "this node is a cluster control plane (it holds the cluster CA); it cannot join \
             another fleet",
        ),
        Ok(None) => {}
        Err(e) => fail(format!("failed to read the cluster CA state: {e}")),
    }
    match store.get_cluster_identity() {
        Ok(Some(identity)) => fail(format!(
            "this node is already enrolled as {} ({}); run `lorica cluster leave` first",
            identity.node_id, identity.node_name
        )),
        Ok(None) => {}
        Err(e) => fail(format!("failed to read the fleet identity: {e}")),
    }
    let schema_version = store
        .schema_version()
        .map(|v| u32::try_from(v).unwrap_or(u32::MAX))
        .unwrap_or_else(|e| fail(format!("failed to read the schema version: {e}")));
    let (spki_der, key_pem) = lorica_cluster::ca::generate_node_keypair()
        .unwrap_or_else(|e| fail(format!("failed to generate the node keypair: {e}")));

    let params = JoinParams {
        enrollment_addr: enrollment_addr.clone(),
        expected_host: expected_host.clone(),
        token: parsed,
        public_key_der: spki_der,
        node_name: node_name.clone(),
        build_version: env!("CARGO_PKG_VERSION").to_string(),
        schema_version,
        timeout: JOIN_TIMEOUT,
    };
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let _ = lorica_cluster::tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    println!("Enrolling with {enrollment_addr} (control plane {control_plane}) as {node_name}...");
    let grant = rt
        .block_on(join(params))
        .unwrap_or_else(|e| fail(format!("join failed: {e}")));
    let cert_not_after = DateTime::parse_from_rfc3339(&grant.cert_not_after)
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or_else(|e| fail(format!("the control plane sent an unreadable expiry: {e}")));
    store
        .set_cluster_identity(&ClusterIdentity {
            node_id: grant.node_id.clone(),
            node_name: node_name.clone(),
            cert_pem: grant.cert_pem,
            key_pem,
            ca_pem: grant.ca_pem,
            control_plane: control_plane.clone(),
            server_name: expected_host,
            enrolled_at: Utc::now(),
            cert_not_after,
        })
        .unwrap_or_else(|e| fail(format!("enrolled, but failed to persist the fleet identity: {e}")));
    println!(
        "Enrolled as node {} ({}) with status {}; certificate valid until {}.",
        grant.node_id,
        node_name,
        grant.status,
        cert_not_after.to_rfc3339()
    );
    if grant.status == "pending" {
        println!(
            "A SuperAdmin must activate this node on the control plane \
             (POST /api/v1/cluster/nodes/{}/activate) before it receives configuration.",
            grant.node_id
        );
    }
    println!("Restart lorica to start the cluster session (this node dials {control_plane}).");
}

/// A client for the loopback management API. The self-signed
/// management certificate has no chain to validate and the target is
/// always 127.0.0.1, hence the accepted invalid certificate (the same
/// trade `lorica unban` makes).
fn management_client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .danger_accept_invalid_certs(true)
        .build()
        .expect("HTTP client")
}

async fn management_login(client: &reqwest::Client, port: u16, user: &str, password: &str) {
    let login_url = format!("https://127.0.0.1:{port}/api/v1/auth/login");
    match client
        .post(&login_url)
        .json(&serde_json::json!({ "username": user, "password": password }))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => {}
        Ok(r) => fail(format!("Login failed ({}). Check credentials.", r.status())),
        Err(e) => fail(format!(
            "Cannot connect to management API on port {port}: {e}. \
             Hint: is lorica running and is --management-port correct?"
        )),
    }
}

/// Read the `data` envelope of a management API answer, or fail with
/// the body.
async fn management_data(response: reqwest::Response, what: &str) -> serde_json::Value {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        fail(format!("{what} failed ({status}): {body}"));
    }
    serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("data").cloned())
        .unwrap_or_else(|| fail(format!("{what}: unexpected answer: {body}")))
}

/// Outcome of the credential-less deregistration probe.
enum Probe {
    /// The control plane refused the node's certificate (or closed the
    /// connection right after mTLS): deregistered on that side.
    Deregistered(String),
    /// The control plane admitted a session: still registered.
    StillRegistered,
    /// Could not reach the control plane: nothing proven.
    Unreachable(String),
}

async fn probe_registration(identity: &ClusterIdentity, schema_version: u32) -> Probe {
    let tls = match client_config(&identity.ca_pem, &identity.cert_pem, &identity.key_pem) {
        Ok(tls) => tls,
        Err(e) => return Probe::Unreachable(format!("local identity unusable: {e}")),
    };
    let connector = TlsConnector::from(Arc::new(tls));
    let server_name = match ServerName::try_from(identity.server_name.clone()) {
        Ok(name) => name,
        Err(e) => return Probe::Unreachable(format!("invalid server name: {e}")),
    };
    let tcp = match tokio::time::timeout(
        PROBE_TIMEOUT,
        tokio::net::TcpStream::connect(identity.control_plane.as_str()),
    )
    .await
    {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(e)) => return Probe::Unreachable(format!("tcp connect: {e}")),
        Err(_) => return Probe::Unreachable("tcp connect timed out".to_string()),
    };
    let tls = match tokio::time::timeout(PROBE_TIMEOUT, connector.connect(server_name, tcp)).await
    {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => return Probe::Deregistered(format!("TLS refused: {e}")),
        Err(_) => return Probe::Unreachable("TLS handshake timed out".to_string()),
    };
    let (endpoint, _incoming) =
        lorica_command::RpcEndpoint::<lorica_cluster::ClusterFrame>::from_stream(tls);
    let handshake = HandshakeConfig::new(schema_version).with_build_version(env!("CARGO_PKG_VERSION"));
    match tokio::time::timeout(
        PROBE_TIMEOUT,
        lorica_cluster::client_handshake(&endpoint, &handshake, &identity.node_name, PROBE_TIMEOUT),
    )
    .await
    {
        Ok(Ok(_)) => Probe::StillRegistered,
        // TLS 1.3 client-certificate failures (revoked serial, unknown
        // identity) surface here: the control plane closes right after
        // the handshake, before any answer.
        Ok(Err(HandshakeError::Transport(e))) => {
            Probe::Deregistered(format!("session refused after mTLS: {e}"))
        }
        Ok(Err(other)) => Probe::Unreachable(format!(
            "the control plane admitted the certificate but refused the session ({other}); \
             nothing proves deregistration"
        )),
        Err(_) => Probe::Unreachable("handshake timed out".to_string()),
    }
}

/// `lorica cluster leave`.
pub fn run_cluster_leave(
    data_dir: &str,
    management_port: u16,
    user: Option<String>,
    password: Option<String>,
) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    if let (Some(user), Some(password)) = (user, password) {
        // Authorised by a SuperAdmin credential: the running instance
        // tells the control plane, wipes and audits.
        rt.block_on(async {
            let client = management_client();
            management_login(&client, management_port, &user, &password).await;
            let url = format!("https://127.0.0.1:{management_port}/api/v1/cluster/leave");
            let response = client
                .post(&url)
                .send()
                .await
                .unwrap_or_else(|e| fail(format!("leave request failed: {e}")));
            let data = management_data(response, "leave").await;
            let notified = data
                .get("control_plane_notified")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            println!(
                "Left the fleet (node {}).",
                data.get("node_id").and_then(|v| v.as_str()).unwrap_or("?")
            );
            if !notified {
                println!(
                    "The control plane could not be notified: revoke this node there \
                     (DELETE /api/v1/cluster/nodes/<id>) so its certificate is on the CRL."
                );
            }
        });
        return;
    }

    // No credential: control-plane-side deregistration must be proven.
    let data_dir = PathBuf::from(data_dir);
    let store = open_store(&data_dir);
    let identity = match store.get_cluster_identity() {
        Ok(Some(identity)) => identity,
        Ok(None) => fail("this node holds no fleet identity (it is not a follower)"),
        Err(e) => fail(format!("failed to read the fleet identity: {e}")),
    };
    let schema_version = store
        .schema_version()
        .map(|v| u32::try_from(v).unwrap_or(u32::MAX))
        .unwrap_or_else(|e| fail(format!("failed to read the schema version: {e}")));
    let _ = lorica_cluster::tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    println!(
        "No credentials given: checking whether {} already deregistered node {}...",
        identity.control_plane, identity.node_id
    );
    match rt.block_on(probe_registration(&identity, schema_version)) {
        Probe::StillRegistered => fail(format!(
            "the control plane still accepts this node ({}). Leaving requires either its \
             deregistration there (DELETE /api/v1/cluster/nodes/{}) or a SuperAdmin \
             credential on the local management API (--user/--password), which tells the \
             control plane, wipes and audits.",
            identity.node_id, identity.node_id
        )),
        Probe::Unreachable(reason) => {
            eprintln!(
                "cannot prove deregistration ({reason}). Revoke the node on the control plane, \
                 or pass --user/--password for a SuperAdmin-authorised leave."
            );
            std::process::exit(2);
        }
        Probe::Deregistered(reason) => {
            println!("The control plane refuses this node ({reason}): deregistered; wiping the fleet identity.");
            let wiped = store
                .delete_cluster_identity()
                .unwrap_or_else(|e| fail(format!("failed to wipe the fleet identity: {e}")));
            // Local audit row (AC #13: audited on both sides). The
            // control plane audited its revocation already.
            match lorica_api::log_store::LogStore::open(&data_dir) {
                Ok(log_store) => {
                    let after = serde_json::json!({
                        "identity_wiped": wiped,
                        "reason": "control plane deregistered this node",
                    });
                    let entry = lorica_api::audit::NewAuditEntry {
                        timestamp: Utc::now().to_rfc3339(),
                        operator_username: "cli".to_string(),
                        operator_role: "local".to_string(),
                        action: "cluster.node.leave".to_string(),
                        target_type: "cluster_node".to_string(),
                        target_id: identity.node_id.clone(),
                        before_payload_hash: String::new(),
                        after_payload_hash: lorica_api::audit::hash_payload(Some(&after)),
                        ip: String::new(),
                        user_agent: "lorica-cli".to_string(),
                    };
                    if let Err(e) = log_store.insert_audit(&entry) {
                        eprintln!("warning: the local audit entry could not be written: {e}");
                    }
                }
                Err(e) => eprintln!("warning: the local audit log could not be opened: {e}"),
            }
            println!(
                "Node {} left the fleet. Restart lorica so it runs standalone.",
                identity.node_id
            );
        }
    }
}

/// `lorica cluster status`.
pub fn run_cluster_status(
    data_dir: &str,
    management_port: u16,
    user: Option<String>,
    password: Option<String>,
) {
    let data_dir = PathBuf::from(data_dir);
    let store = open_store(&data_dir);
    let is_control_plane = store
        .get_cluster_ca()
        .unwrap_or_else(|e| fail(format!("failed to read the cluster CA state: {e}")))
        .is_some();
    let identity = store
        .get_cluster_identity()
        .unwrap_or_else(|e| fail(format!("failed to read the fleet identity: {e}")));
    let generation = store.cluster_config_generation().unwrap_or(0);
    println!("Build version: {}", env!("CARGO_PKG_VERSION"));
    match (&identity, is_control_plane) {
        (Some(identity), _) => {
            println!("Role: follower");
            println!("Node id: {}", identity.node_id);
            println!("Node name: {}", identity.node_name);
            println!("Control plane: {}", identity.control_plane);
            println!("Enrolled at: {}", identity.enrolled_at.to_rfc3339());
            println!(
                "Certificate valid until: {}",
                identity.cert_not_after.to_rfc3339()
            );
        }
        (None, true) => println!("Role: control plane (cluster CA initialised)"),
        (None, false) => println!("Role: standalone"),
    }
    println!("Applied configuration generation: {generation}");

    let (Some(user), Some(password)) = (user, password) else {
        println!("(Pass --user/--password for the live connection state and the roster.)");
        return;
    };
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let client = management_client();
        management_login(&client, management_port, &user, &password).await;
        let url = format!("https://127.0.0.1:{management_port}/api/v1/cluster/status");
        let response = client
            .get(&url)
            .send()
            .await
            .unwrap_or_else(|e| fail(format!("status request failed: {e}")));
        let data = management_data(response, "status").await;
        println!("Live status:");
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_else(|_| data.to_string())
        );
    });
}

/// `lorica cluster token`.
pub fn run_cluster_token(
    management_port: u16,
    ttl_seconds: Option<u64>,
    node_name: Option<String>,
    source_cidr: Option<String>,
    user: String,
    password: String,
) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let client = management_client();
        management_login(&client, management_port, &user, &password).await;
        let url = format!("https://127.0.0.1:{management_port}/api/v1/cluster/tokens");
        let response = client
            .post(&url)
            .json(&serde_json::json!({
                "ttl_seconds": ttl_seconds,
                "node_name": node_name,
                "source_cidr": source_cidr,
            }))
            .send()
            .await
            .unwrap_or_else(|e| fail(format!("token request failed: {e}")));
        let data = management_data(response, "token mint").await;
        let token_value = data
            .get("token")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| fail("token mint: no token in the answer"));
        println!(
            "Join token (shown once; expires at {}):",
            data.get("expires_at").and_then(|v| v.as_str()).unwrap_or("?")
        );
        println!("{token_value}");
        println!();
        println!("On the joining node, hand it over on standard input, never on the command line:");
        println!("  lorica cluster join --control-plane <control-plane-host:port> --token-stdin");
        println!("The enrollment window stays open until this token is redeemed, revoked or expires.");
    });
}
