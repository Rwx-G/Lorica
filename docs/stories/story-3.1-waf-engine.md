# Story 3.1: WAF Engine with OWASP CRS

**Epic:** [Epic 3 - Intelligence](../prd/epic-3-intelligence.md)
**Status:** Draft
**Priority:** P2
**Depends on:** Epic 2 complete

---

As an infrastructure engineer,
I want an optional WAF that detects and blocks common attacks,
so that my backends are protected without needing a separate WAF tool.

## Acceptance Criteria

1. `lorica-waf` crate created
2. OWASP CRS ruleset loading and parsing
3. WAF evaluation pipeline: inspect request headers, path, query, body against rules
4. Two modes per route: detection-only (log) or blocking (403)
5. WAF toggle per route in dashboard and API
6. Alerting by default: even without WAF enabled, suspicious patterns logged
7. WAF events visible in dashboard security panel
8. Performance: < 0.5ms added latency for WAF evaluation

## Integration Verification

- IV1: Known attack patterns (SQL injection, XSS, path traversal) are detected
- IV2: WAF in blocking mode returns 403 for matched requests
- IV3: WAF in detection mode logs the event but proxies the request normally
- IV4: Routes without WAF enabled have zero WAF latency overhead

## Tasks

- [ ] Create `lorica-waf` crate
- [ ] Research OWASP CRS ruleset format (SecLang/ModSecurity syntax)
- [ ] Implement rule parser for CRS subset
- [ ] Implement WAF evaluation pipeline
- [ ] Integrate into ProxyHttp::request_filter() phase
- [ ] Implement detection vs blocking modes
- [ ] Implement default alerting (suspicious pattern logging)
- [ ] Add WAF toggle to route configuration
- [ ] Build security panel in dashboard
- [ ] Benchmark WAF evaluation latency
- [ ] Write tests with known attack patterns

## Dev Notes

- WAF evaluation must be async and non-blocking on the proxy hot path
- Consider evaluating only a subset of CRS rules initially (SQL injection, XSS, path traversal)
- OWASP CRS rules use ModSecurity SecLang syntax - need a Rust parser
- Routes without WAF enabled should skip evaluation entirely (zero overhead)
- WAF events stored in memory for dashboard display, emitted to stdout for SIEM
