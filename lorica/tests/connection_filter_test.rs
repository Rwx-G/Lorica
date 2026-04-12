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

//! End-to-end wiring tests for the connection pre-filter.
//!
//! Covers: persistence of the new `GlobalSettings` fields across a store
//! round-trip, and observable hot-reload semantics - a config change pushed
//! through `reload_proxy_config` must be visible to the filter without
//! rebuilding it, matching the production path taken by both workers (via
//! the command channel) and the single-process reload watch.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use lorica::connection_filter::GlobalConnectionFilter;
use lorica::proxy_wiring::ProxyConfig;
use lorica::reload::reload_proxy_config;
use lorica_config::ConfigStore;
use lorica_core::listeners::ConnectionFilter;

fn addr(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), 0)
}

#[tokio::test]
async fn connection_filter_cidrs_persist_round_trip() {
    let store = ConfigStore::open_in_memory().unwrap();
    let mut settings = store.get_global_settings().unwrap();
    settings.connection_deny_cidrs = vec!["203.0.113.0/24".into(), "10.0.0.5".into()];
    settings.connection_allow_cidrs = vec!["192.168.0.0/16".into()];
    store.update_global_settings(&settings).unwrap();

    let reloaded = store.get_global_settings().unwrap();
    assert_eq!(
        reloaded.connection_deny_cidrs,
        vec!["203.0.113.0/24".to_string(), "10.0.0.5".to_string()]
    );
    assert_eq!(
        reloaded.connection_allow_cidrs,
        vec!["192.168.0.0/16".to_string()]
    );
}

#[tokio::test]
async fn reload_applies_cidrs_to_filter() {
    let store = ConfigStore::open_in_memory().unwrap();
    let store = Arc::new(tokio::sync::Mutex::new(store));
    let proxy_config = Arc::new(arc_swap::ArcSwap::from_pointee(ProxyConfig::default()));
    let filter = Arc::new(GlobalConnectionFilter::empty());

    // Empty settings -> allow-all
    reload_proxy_config(&store, &proxy_config, Some(&filter))
        .await
        .unwrap();
    assert!(filter.should_accept(Some(&addr(1, 2, 3, 4))).await);

    // Stage a deny policy via settings.
    {
        let s = store.lock().await;
        let mut settings = s.get_global_settings().unwrap();
        settings.connection_deny_cidrs = vec!["10.0.0.0/8".into()];
        s.update_global_settings(&settings).unwrap();
    }

    reload_proxy_config(&store, &proxy_config, Some(&filter))
        .await
        .unwrap();
    assert!(!filter.should_accept(Some(&addr(10, 1, 2, 3))).await);
    assert!(filter.should_accept(Some(&addr(8, 8, 8, 8))).await);

    // Swap to default-deny via an allow list.
    {
        let s = store.lock().await;
        let mut settings = s.get_global_settings().unwrap();
        settings.connection_deny_cidrs = vec![];
        settings.connection_allow_cidrs = vec!["192.168.0.0/16".into()];
        s.update_global_settings(&settings).unwrap();
    }

    reload_proxy_config(&store, &proxy_config, Some(&filter))
        .await
        .unwrap();
    assert!(filter.should_accept(Some(&addr(192, 168, 1, 1))).await);
    assert!(!filter.should_accept(Some(&addr(10, 0, 0, 1))).await);

    // Clear everything -> back to allow-all.
    {
        let s = store.lock().await;
        let mut settings = s.get_global_settings().unwrap();
        settings.connection_allow_cidrs = vec![];
        s.update_global_settings(&settings).unwrap();
    }
    reload_proxy_config(&store, &proxy_config, Some(&filter))
        .await
        .unwrap();
    assert!(filter.should_accept(Some(&addr(10, 0, 0, 1))).await);
}

// ---------------------------------------------------------------------------
// TCP-level end-to-end
//
// Runs a real TCP accept loop that consults `GlobalConnectionFilter` exactly
// the way `lorica-core/src/listeners/l4.rs` does in production: on each
// accept it calls `should_accept(peer_addr)` and drops the stream when the
// filter rejects. Lets us prove the full behaviour path (TCP SYN accepted,
// filter consulted, stream dropped, client observes EOF) against the actual
// filter impl shipped in the binary - without standing up an HTTP server.
// ---------------------------------------------------------------------------

async fn serve_with_filter(
    filter: Arc<GlobalConnectionFilter>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> std::net::SocketAddr {
    use tokio::io::AsyncWriteExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bound = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while !stop.load(std::sync::atomic::Ordering::SeqCst) {
            let accept = tokio::time::timeout(
                std::time::Duration::from_millis(50),
                listener.accept(),
            )
            .await;
            let (mut stream, peer) = match accept {
                Ok(Ok(pair)) => pair,
                _ => continue,
            };
            if !filter.should_accept(Some(&peer)).await {
                // Mirrors l4.rs:386-408: reject => drop stream, never progress
                // to TLS handshake or HTTP parsing.
                drop(stream);
                continue;
            }
            // Accepted: write a sentinel byte so the client can distinguish
            // "reached the app layer" from "dropped at the filter".
            let _ = stream.write_all(b"K").await;
            let _ = stream.shutdown().await;
        }
    });
    bound
}

async fn read_one_byte(addr: std::net::SocketAddr) -> Option<u8> {
    use tokio::io::AsyncReadExt;
    let mut stream = match tokio::net::TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(_) => return None,
    };
    let mut buf = [0u8; 1];
    match tokio::time::timeout(
        std::time::Duration::from_millis(500),
        stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) if n >= 1 => Some(buf[0]),
        Ok(Ok(_)) => None, // EOF: filter dropped the stream
        Ok(Err(_)) => None,
        Err(_) => None,
    }
}

#[tokio::test]
async fn tcp_accept_drops_denied_peer() {
    let filter = Arc::new(GlobalConnectionFilter::new(
        lorica::connection_filter::ConnectionFilterPolicy::from_cidrs(
            &[],
            &["127.0.0.1/32".into()],
        ),
    ));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let bound = serve_with_filter(Arc::clone(&filter), Arc::clone(&stop)).await;

    assert_eq!(
        read_one_byte(bound).await,
        None,
        "loopback peer must be dropped before reaching the app layer"
    );

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[tokio::test]
async fn tcp_accept_hot_reload_flips_behaviour_midstream() {
    // Start allow-all, verify accept. Push a deny policy, verify reject on
    // the NEXT connection (no listener restart). Push an allow, verify
    // accept again. Proves the runtime path used by `reload_proxy_config`
    // actually reaches the accept loop.
    let filter = Arc::new(GlobalConnectionFilter::empty());
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let bound = serve_with_filter(Arc::clone(&filter), Arc::clone(&stop)).await;

    assert_eq!(read_one_byte(bound).await, Some(b'K'), "allow-all must pass");

    filter.reload(lorica::connection_filter::ConnectionFilterPolicy::from_cidrs(
        &[],
        &["127.0.0.0/8".into()],
    ));
    assert_eq!(
        read_one_byte(bound).await,
        None,
        "post-reload deny must drop on the next accept without rebuilding the listener"
    );

    filter.reload(lorica::connection_filter::ConnectionFilterPolicy::from_cidrs(&[], &[]));
    assert_eq!(
        read_one_byte(bound).await,
        Some(b'K'),
        "post-reload back to allow-all must accept again"
    );

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[tokio::test]
async fn reload_without_filter_leaves_filter_untouched() {
    // Health ticks and supervisor reloads pass `None` for the filter. That
    // code path must leave any previously-installed policy in place - this
    // guards the supervisor/worker split where only the worker owns the
    // listener's filter.
    let store = ConfigStore::open_in_memory().unwrap();
    let store = Arc::new(tokio::sync::Mutex::new(store));
    let proxy_config = Arc::new(arc_swap::ArcSwap::from_pointee(ProxyConfig::default()));
    let filter = Arc::new(GlobalConnectionFilter::empty());

    filter.reload(lorica::connection_filter::ConnectionFilterPolicy::from_cidrs(
        &[],
        &["203.0.113.0/24".into()],
    ));

    reload_proxy_config(&store, &proxy_config, None)
        .await
        .unwrap();

    // Filter unchanged: the pre-installed deny must still apply.
    assert!(!filter.should_accept(Some(&addr(203, 0, 113, 1))).await);
    assert!(filter.should_accept(Some(&addr(1, 2, 3, 4))).await);
}
