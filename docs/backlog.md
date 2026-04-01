# Technical Backlog

Items identified during development that are deferred to future stories.

## High Priority

| Source | Description | References |
|--------|-------------|------------|
| Wiring audit | `compression_enabled` - Pingora has gzip/brotli/zstd in lorica-core but compression is a module-level setting (level 0 = disabled). Per-route activation requires modifying the ResponseCompressionCtx which is not directly accessible from ProxyHttp callbacks. Needs Pingora module extension. | `lorica-core/src/protocols/http/compression/`, `lorica-proxy/src/proxy_trait.rs:57` |
| Wiring audit | `retry_attempts` - Pingora has `max_retries` at service level but not per-route. `fail_to_connect()` returns an Error, not a retry signal. Per-route retry needs proxy flow override or service-level config. | `lorica-proxy/src/lib.rs:122`, `proxy_trait.rs:505` |

## Medium Priority

| Source | Description | References |
|--------|-------------|------------|

## Low Priority

| Source | Description | References |
|--------|-------------|------------|
