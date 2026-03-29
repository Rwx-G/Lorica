# Technical Backlog

Items identified during development that are deferred to future stories.

## High Priority

| Source | Description | References |
|--------|-------------|------------|

## Medium Priority

| Source | Description | References |
|--------|-------------|------------|
| Epic 1.8 QA | Add API-triggered config reload on route/backend CRUD mutations | lorica-api/src/routes.rs, lorica-api/src/backends.rs |

## Low Priority

| Source | Description | References |
|--------|-------------|------------|
| Epic 1.5 QA | Add light theme toggle in dashboard Settings screen | Story 1.10 |
| Epic 1.7 QA | Persist self-signed certificate preference to UserPreference API | Story 1.10, Certificates.svelte:57 |
| Epic 1.7 QA | Persist expiration threshold config to GlobalSettings via Settings API | Story 1.10, Certificates.svelte:20-21 |
| Epic 1.10 QA | Validate notification config JSON format on backend | lorica-api/src/settings.rs:create_notification |
| Epic 1.10 QA | Add file size limit on TOML import to prevent memory exhaustion | lorica-api/src/config.rs:import_config |
| Epic 1.10 QA | Add notification connection test endpoint (verify SMTP/webhook reachability) | lorica-api/src/settings.rs |
