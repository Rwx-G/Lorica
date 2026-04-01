# Technical Backlog

Items identified during QA traceability audit (2026-04-01).

## High Priority

| Source | Description | References |
|--------|-------------|------------|

## Medium Priority

| Source | Description | References |
|--------|-------------|------------|
| 7.3 AC4 | Global connection limit not implemented (only per-route `max_connections` exists). Decide: implement global cap or formally descope. | `lorica/src/proxy_wiring.rs` |

## Low Priority

| Source | Description | References |
|--------|-------------|------------|
| NFR2+11 | Validation script created but not yet executed on a real Linux machine. Run `docs/testing/nfr-validate.sh` after .deb install. | `docs/testing/nfr-validate.sh` |
