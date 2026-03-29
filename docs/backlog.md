# Technical Backlog

Items identified during development that are deferred to future stories.

## High Priority

| Source | Description | References |
|--------|-------------|------------|

## Medium Priority

| Source | Description | References |
|--------|-------------|------------|
| Story 1.1 QA (C1) | Decouple proxy from cache crate - proxy has deep coupling with lorica-cache, preventing its removal | lorica-proxy/src/proxy_cache.rs, lorica-proxy/src/proxy_trait.rs |
| Story 1.1 QA (C3) | Migrate nix 0.24 to 0.29+ - API breaking changes in socket/fd handling require careful refactoring | lorica-core/src/server/transfer_fd/mod.rs, lorica-core/src/protocols/l4/stream.rs |

## Low Priority

| Source | Description | References |
|--------|-------------|------------|
| Story 1.1 QA (C2) | Remove cf-rustracing/cf-rustracing-jaeger from cache crate (Cloudflare-specific tracing) | lorica-cache/Cargo.toml, lorica-cache/src/trace.rs |
| Story 1.1 QA (C4) | Clean up dead cfg feature branches (openssl, boringssl, s2n, openssl_derived warnings) | lorica-core/src/lib.rs, lorica-core/src/connectors/, lorica-core/src/listeners/ |
