# Story 7.3: Anti-DDoS Protection

**Epic:** [Epic 7 - HTTP Caching & DDoS Protection](../prd/epic-7-cache-and-protection.md)
**Status:** Draft
**Priority:** P0
**Depends on:** Story 7.2 (per-route rate limiting)

---

As an infrastructure engineer,
I want automatic DDoS mitigation to protect the proxy and backends from volumetric and application-layer attacks.

## Acceptance Criteria

1. Slowloris detection: abort connections that send headers too slowly (configurable threshold)
2. Auto-ban: IPs exceeding rate limits N times get temporarily banned (configurable ban_duration_s)
3. Ban list stored in memory with auto-expiry
4. Global connection limit (max total proxy connections, reject with 503)
5. Request flood detection: if global RPS exceeds threshold, enable stricter per-IP limits
6. Ban list visible and manageable in dashboard (view, unban)
7. Ban events dispatched to notification system (AlertType::IpBanned)

## Integration Verification

- IV1: Slow header sender gets disconnected after threshold exceeded
- IV2: IP exceeding rate limits repeatedly gets banned and receives immediate 403
- IV3: Ban list displays in dashboard and manual unban takes effect immediately

## Tasks

- [ ] Implement slowloris detection in connection handler (header receive timeout)
- [ ] Add configurable header_timeout_s field to global proxy settings (default 10s)
- [ ] Implement auto-ban tracker (per-IP rate limit violation counter with time window)
- [ ] Add configurable ban_threshold (violations before ban, default 5) and ban_duration_s (default 600)
- [ ] Implement ban list with DashMap and auto-expiry via background task
- [ ] Check ban list in early request_filter phase, return 403 for banned IPs
- [ ] Implement global connection limit (AtomicUsize counter, configurable max_global_connections)
- [ ] Return 503 when global connection limit exceeded
- [ ] Implement flood detection: track global RPS, tighten per-IP limits when threshold exceeded
- [ ] Add configurable flood_threshold_rps and flood_strict_rps fields to global settings
- [ ] Dispatch AlertType::IpBanned event to notification system on auto-ban
- [ ] Add ban list API endpoints (GET /api/v1/bans, DELETE /api/v1/bans/:ip)
- [ ] Add dashboard ban list view with IP, ban reason, expiry time, and unban button
- [ ] Write tests for slowloris detection and connection abort
- [ ] Write tests for auto-ban escalation (violation counting and ban trigger)
- [ ] Write tests for ban expiry and automatic removal
- [ ] Write tests for global connection limit enforcement
- [ ] Write tests for flood detection mode activation and stricter limits
- [ ] Write tests for manual unban via API

## Dev Notes

- Slowloris detection: use Pingora's read timeout on header phase - if full headers not received within header_timeout_s, drop the connection
- Ban list uses DashMap<IpAddr, BanEntry> for lock-free concurrent access
- BanEntry contains: banned_at timestamp, expires_at timestamp, reason enum (RateLimit, Flood)
- Background task sweeps expired bans every 60s to free memory
- Auto-ban threshold is a sliding window: N violations within a configurable window (default 60s)
- Banned IPs get 403 Forbidden with no body (minimal resource usage)
- Flood detection: when global RPS exceeds flood_threshold_rps, halve all per-IP rate limits
- Flood mode deactivates automatically when global RPS drops below 80% of threshold
- Global connection limit is a hard cap - includes all active connections across all routes
- AlertType::IpBanned notification includes IP, reason, ban duration, and trigger route
- Ban list is in-memory only - intentionally not persisted (bans are temporary by design)
