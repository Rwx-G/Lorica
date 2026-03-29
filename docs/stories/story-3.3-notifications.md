# Story 3.3: Notification Channels

**Epic:** [Epic 3 - Intelligence](../prd/epic-3-intelligence.md)
**Status:** Draft
**Priority:** P2
**Depends on:** Epic 1 complete

---

As an infrastructure engineer,
I want to receive notifications for critical events via email or webhook,
so that I am alerted without watching the dashboard constantly.

## Acceptance Criteria

1. `lorica-notify` crate created
2. Notification types: cert_expiring, backend_down, waf_alert, config_changed
3. Stdout channel: always on, structured JSON log events
4. Email channel: SMTP configuration in settings, configurable alert types
5. Webhook channel: URL + optional auth header, configurable alert types
6. Notification preferences per alert type (enable/disable per channel)
7. Test notification button in dashboard settings
8. Notification history viewable in dashboard

## Integration Verification

- IV1: Certificate approaching expiration triggers configured notifications
- IV2: Backend going down triggers notification within configured threshold
- IV3: Webhook delivers valid JSON payload to configured URL

## Tasks

- [ ] Create `lorica-notify` crate
- [ ] Define AlertEvent types (CertExpiring, BackendDown, WafAlert, ConfigChanged)
- [ ] Implement StdoutChannel (always on, JSON structured events)
- [ ] Implement EmailChannel using lettre crate (SMTP)
- [ ] Implement WebhookChannel using reqwest (HTTP POST with JSON)
- [ ] Implement notification preference storage and lookup
- [ ] Add notification config to dashboard settings screen
- [ ] Implement test notification button
- [ ] Implement notification history (in-memory ring buffer)
- [ ] Add notification history view to dashboard
- [ ] Write tests for each channel
- [ ] Write tests for preference-based routing

## Dev Notes

- Three channels only: stdout, email, webhook (no Slack/Telegram/Discord)
- Stdout is always on - other channels are opt-in
- Email uses lettre crate with SMTP configuration
- Webhook sends POST with JSON body and optional Authorization header
- Notification history keeps last 100 events in memory
