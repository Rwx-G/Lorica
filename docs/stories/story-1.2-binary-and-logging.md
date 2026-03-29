# Story 1.2: Basic Binary and Structured Logging

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Done
**Priority:** P0
**Depends on:** Story 1.1

---

As an infrastructure engineer,
I want a `lorica` binary with structured logging and systemd readiness,
so that I can run Lorica as a service with proper log output.

## Acceptance Criteria

1. `lorica` binary crate created with clap CLI (minimal flags: `--version`, `--data-dir`)
2. `tracing` + `tracing-subscriber` integrated for structured JSON logging to stdout
3. Log levels configurable via `RUST_LOG` or `--log-level` flag
4. Startup banner with version, data directory path, and management port
5. SIGTERM/SIGINT handled for graceful shutdown
6. Example systemd unit file created in `dist/lorica.service`

## Integration Verification

- IV1: Binary starts and shuts down cleanly
- IV2: JSON log output is parseable by standard tools (jq)
- IV3: systemd unit file passes `systemd-analyze verify`

## Tasks

- [x] Create `lorica` binary crate in workspace (added [[bin]] to existing facade crate)
- [x] Add clap CLI with `--version`, `--data-dir`, `--log-level`, `--management-port`
- [x] Integrate tracing + tracing-subscriber with JSON formatter
- [x] Implement startup banner log message (version, data_dir, management_port)
- [x] Implement signal handlers (SIGTERM, SIGINT on Unix; Ctrl+C on Windows)
- [x] Create `dist/lorica.service` systemd unit file (with security hardening)
- [x] Test binary starts and shuts down cleanly
- [x] Test JSON log output with jq

## Dev Notes

- The binary crate should be at workspace root level as `lorica/`
- Use `tracing_subscriber::fmt::json()` for structured output
- systemd unit file should include basic hardening (PrivateTmp, NoNewPrivileges)
- Data directory default: `/var/lib/lorica` on Linux, `./data` for development
