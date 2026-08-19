# TLS certificate resolver lifecycle

The SNI certificate resolver (`lorica-tls::cert_resolver::CertResolver`)
selects a `rustls` `CertifiedKey` per TLS handshake from the SNI
hostname. It is lock-free on the read path (`arc-swap`) and hot-swapped
on config change with no dropped connections.

As of v1.6.0 (Story 8.5) the resolver has two independent write paths
that never block each other on the network:

1. **Reload** swaps certificate bodies.
2. **OCSP refresh** swaps OCSP staples.

## Reload: certificate bodies only

`lorica::reload::reload_cert_resolver` is called on every config change
(single-process `config_reload_rx` watch, worker two-phase
`ConfigReloadCommit` RPC, legacy `ConfigReload` fallback). It:

1. Reads the certificates referenced by at least one route from the
   store.
2. Builds `CertData` with `ocsp_response: None` - **no OCSP fetch on
   this path**.
3. Calls `CertResolver::reload`, which is partial-tolerant: a malformed
   row (truncated key, wrong encryption key, mismatched cert/key pair)
   is logged and skipped, and the rest of the batch still publishes.
   `ReloadStats::skipped_domains` names each skipped vhost.
4. Publishes the new table with a single `arc-swap`.
5. Fires `OCSP_REFRESH_NOTIFY` so the background loop staples the fresh
   certs within a few seconds.

Before v1.6.0 the reload fetched OCSP staples inline with a
10 s-per-responder timeout, so a slow or unreachable responder delayed
the TLS listener from serving a freshly installed certificate by up to
10 seconds. Deferring OCSP off this path makes a new cert observable on
the listener in ~200 ms.

## OCSP refresh: background task

`lorica::startup::spawn_ocsp_refresh_loop` runs once per process that
owns a resolver (single-process, and each worker in worker mode). It:

1. Wakes every 6 hours, or immediately when `OCSP_REFRESH_NOTIFY` fires
   after a reload. (The story's `min(nextUpdate - now, 6h)` cadence
   collapses to a flat 6 h for every real-world CA, whose OCSP
   `nextUpdate` is days out, so the 6 h cap always wins.)
2. Re-reads the route-referenced certs from the store.
3. Fetches a fresh staple per certificate over the shared
   `lorica_tls::ocsp::OCSP_CLIENT` connection pool (redirects disabled -
   the responder URL comes from the attacker-influenced AIA extension).
4. Calls `CertResolver::refresh_staples`, which rebuilds each affected
   `CertifiedKey` with the new staple bytes by cloning the already
   parsed cert chain and the `Arc`-shared signing key (no PEM re-parse),
   then publishes the whole table with one `arc-swap`. A domain whose
   fetch failed keeps its previous staple; a body-only reload with no
   staple yet simply has none until the next successful fetch.

In-flight TLS handshakes are unaffected by either swap: they keep
serving the `CertifiedKey` they already negotiated.

## Metrics

- `lorica_cert_resolver_reload_total{result="ok|fail"}` - reload
  outcomes (per-worker aggregated).
- `lorica_ocsp_refresh_total{result="ok|fail"}` - background staple
  fetches by outcome (per-worker aggregated).
- `lorica_cert_resolver_active_domains` - distinct domains served,
  refreshed supervisor-side from the store on every `/metrics` scrape.
- `lorica_cert_resolver_pending_ocsp_seconds{domain}` - seconds since a
  domain last received a fresh staple (0 right after a refresh). Set
  in-process by the loop; like every runtime gauge it is authoritative
  in single-process mode and not shipped to the supervisor in worker
  mode (the cross-worker OCSP signal there is `ocsp_refresh_total`).
