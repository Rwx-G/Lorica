# Technical Backlog

Items identified during QA traceability audit (2026-04-01).

## High Priority

| Source | Description | References |
|--------|-------------|------------|

## Medium Priority

| Source | Description | References |
|--------|-------------|------------|
| 7.3 AC4 | Global connection limit not implemented (only per-route `max_connections` exists). Decide: implement global cap or formally descope. | `lorica/src/proxy_wiring.rs` |
| 7.2 AC5 | `X-RateLimit-Reset` header hardcoded to "1" instead of actual Unix timestamp per HTTP spec | `lorica/src/proxy_wiring.rs:1215` |
| 4.3 AC4 | EWMA scores exposed in Prometheus `/metrics` but not shown per-backend in the web dashboard Backends table | `lorica-api/src/backends.rs`, `lorica-api/src/metrics.rs` |

## Low Priority

| Source | Description | References |
|--------|-------------|------------|
| NFR2 | 10k concurrent connections NFR has no automated soak/load test validating it | E2E suite covers functional, not scale |
| NFR11 | Memory stability NFR has no long-running soak test (LRU caps exist but no automated verification) | Could add a CI nightly soak test |
