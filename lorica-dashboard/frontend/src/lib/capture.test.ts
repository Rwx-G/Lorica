import { describe, it, expect } from 'vitest';

import type { CaptureRuleResponse } from './api';
import {
  captureFormFromRule,
  describeEmit,
  emptyCaptureForm,
  expiresAtFrom,
  formatTimeUntil,
  hasEmitCondition,
  parseExactStatuses,
  remainingBudget,
  toCaptureRuleRequest,
  validateCaptureForm,
} from './capture';

function rule(overrides: Partial<CaptureRuleResponse> = {}): CaptureRuleResponse {
  return {
    id: 'cap-1',
    name: 'checkout 5xx',
    route_id: 'route-1',
    enabled: true,
    match: {
      source_cidrs: ['10.0.0.0/8'],
      methods: ['POST'],
      path_prefix: '/checkout',
      path_regex: null,
      headers: [],
    },
    emit: { always: false, status: ['server_error', { exact: 499 }], min_latency_ms: 250, upstream_error: true },
    capture: { request_body: true, response_body: false, request_body_max_bytes: 1024, response_body_max_bytes: 2048 },
    limits: { max_captures: 100, rate_per_minute: 10, ttl_seconds: 3600 },
    output: { dir: '/var/lib/lorica/captures', max_dir_bytes: 1_000_000 },
    redact: { headers: ['X-Api-Key'], query: ['token'] },
    created_by: 'admin',
    created_at: '2026-01-01T00:00:00Z',
    expires_at: '2026-01-01T01:00:00Z',
    captures_emitted: 42,
    captures_dropped: 3,
    ...overrides,
  };
}

describe('validateCaptureForm', () => {
  it('refuses a form without a route', () => {
    const f = emptyCaptureForm();
    f.name = 'r';
    expect(validateCaptureForm(f)).toMatch(/route/i);
  });

  it('refuses a form with no emit condition and no acknowledgement', () => {
    // The unbounded rule: every request on the route, silently.
    const f = emptyCaptureForm('route-1');
    f.name = 'r';
    f.statusServerError = false;
    expect(hasEmitCondition(f)).toBe(false);
    expect(validateCaptureForm(f)).toMatch(/acknowledge/i);
  });

  it('accepts a form with no condition once "always" is acknowledged', () => {
    const f = emptyCaptureForm('route-1');
    f.name = 'r';
    f.statusServerError = false;
    f.always = true;
    expect(validateCaptureForm(f)).toBe('');
    expect(toCaptureRuleRequest(f).emit).toEqual({
      always: true,
      status: [],
      min_latency_ms: null,
      upstream_error: false,
    });
  });

  it('refuses "always" combined with a condition, as the server does', () => {
    const f = emptyCaptureForm('route-1');
    f.name = 'r';
    f.always = true;
    expect(validateCaptureForm(f)).toMatch(/cannot be combined/);
  });

  it('accepts each condition on its own', () => {
    for (const set of [
      (f: ReturnType<typeof emptyCaptureForm>) => (f.statusServerError = true),
      (f: ReturnType<typeof emptyCaptureForm>) => (f.statusExact = '502'),
      (f: ReturnType<typeof emptyCaptureForm>) => (f.minLatencyMs = '250'),
      (f: ReturnType<typeof emptyCaptureForm>) => (f.upstreamError = true),
    ]) {
      const f = emptyCaptureForm('route-1');
      f.name = 'r';
      f.statusServerError = false;
      set(f);
      expect(validateCaptureForm(f)).toBe('');
    }
  });

  it('refuses a malformed exact status, a zero rate and a TTL past seven days', () => {
    const f = emptyCaptureForm('route-1');
    f.name = 'r';
    f.statusExact = '50x';
    expect(validateCaptureForm(f)).toMatch(/Exact statuses/);
    f.statusExact = '';
    f.ratePerMinute = 0;
    expect(validateCaptureForm(f)).toMatch(/Rate per minute/);
    f.ratePerMinute = 10;
    f.ttlSeconds = 7 * 24 * 3600 + 1;
    expect(validateCaptureForm(f)).toMatch(/TTL/);
  });
});

describe('toCaptureRuleRequest', () => {
  it('builds the server body from the form', () => {
    const f = emptyCaptureForm('route-1');
    f.name = '  checkout  ';
    f.sourceCidrs = '10.0.0.0/8\n\n192.0.2.10\n';
    f.methods = 'post, get';
    f.pathPrefix = '/checkout';
    f.statusExact = '502 504';
    f.minLatencyMs = '250';
    f.redactHeaders = 'X-Api-Key\nX-Session';
    const body = toCaptureRuleRequest(f);
    expect(body.name).toBe('checkout');
    expect(body.match?.source_cidrs).toEqual(['10.0.0.0/8', '192.0.2.10']);
    expect(body.match?.methods).toEqual(['POST', 'GET']);
    expect(body.match?.path_prefix).toBe('/checkout');
    expect(body.match?.path_regex).toBeNull();
    expect(body.emit?.status).toEqual(['server_error', { exact: 502 }, { exact: 504 }]);
    expect(body.emit?.min_latency_ms).toBe(250);
    expect(body.output?.dir).toBeNull();
    expect(body.redact?.headers).toEqual(['X-Api-Key', 'X-Session']);
  });

  it('round-trips a stored rule through the form', () => {
    const stored = rule();
    const body = toCaptureRuleRequest(captureFormFromRule(stored));
    expect(body.match).toEqual(stored.match);
    expect(body.emit).toEqual(stored.emit);
    expect(body.capture).toEqual(stored.capture);
    expect(body.limits).toEqual(stored.limits);
    expect(body.output).toEqual(stored.output);
    expect(body.redact).toEqual(stored.redact);
  });
});

describe('row figures', () => {
  it('shows the expiry the TTL produces, anchored on creation', () => {
    const anchor = new Date('2026-01-01T00:00:00Z');
    expect(expiresAtFrom(anchor, 3600).toISOString()).toBe('2026-01-01T01:00:00.000Z');
    expect(expiresAtFrom(anchor, Number.NaN).toISOString()).toBe(anchor.toISOString());
  });

  it('computes the remaining budget and never goes negative', () => {
    expect(remainingBudget(rule())).toBe(58);
    expect(remainingBudget(rule({ captures_emitted: 500 }))).toBe(0);
  });

  it('formats the time to expiry in the coarsest useful unit', () => {
    const now = new Date('2026-01-01T00:00:00Z');
    expect(formatTimeUntil(new Date('2026-01-01T00:00:30Z'), now)).toBe('in 30s');
    expect(formatTimeUntil(new Date('2026-01-01T00:42:10Z'), now)).toBe('in 42m');
    expect(formatTimeUntil(new Date('2026-01-01T03:05:00Z'), now)).toBe('in 3h 5m');
    expect(formatTimeUntil(new Date('2026-01-04T02:00:00Z'), now)).toBe('in 3d 2h');
    expect(formatTimeUntil(new Date('2025-12-31T00:00:00Z'), now)).toBe('expired');
  });

  it('parses exact statuses and refuses what is not one', () => {
    expect(parseExactStatuses('502, 504')).toEqual([502, 504]);
    expect(parseExactStatuses('')).toEqual([]);
    expect(parseExactStatuses('99')).toBeNull();
    expect(parseExactStatuses('600')).toBeNull();
  });

  it('describes the emit block in one line', () => {
    expect(describeEmit(rule().emit)).toBe('status 5xx, 499 or latency >= 250 ms or upstream error');
    expect(describeEmit({ always: true, status: [], min_latency_ms: null, upstream_error: false })).toBe(
      'every request',
    );
  });
});
