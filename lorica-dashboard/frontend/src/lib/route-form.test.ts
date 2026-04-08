import { describe, it, expect } from 'vitest';
import type { RouteResponse } from './api';
import {
  validateRouteForm,
  validateHostname,
  routeToFormState,
  formStateToCreateRequest,
  getModifiedFields,
  ROUTE_DEFAULTS,
  type RouteFormState,
} from './route-form';

// ---------------------------------------------------------------------------
// validateHostname
// ---------------------------------------------------------------------------

describe('validateHostname', () => {
  it('returns error for empty hostname', () => {
    expect(validateHostname('')).toBe('Hostname is required');
    expect(validateHostname('   ')).toBe('Hostname is required');
  });

  it('accepts catch-all hostname _', () => {
    expect(validateHostname('_')).toBe('');
  });

  it('accepts valid hostnames', () => {
    expect(validateHostname('example.com')).toBe('');
    expect(validateHostname('sub.example.com')).toBe('');
    expect(validateHostname('a.b.c.d.e')).toBe('');
    expect(validateHostname('localhost')).toBe('');
  });

  it('accepts wildcard hostnames', () => {
    expect(validateHostname('*.example.com')).toBe('');
  });

  it('rejects invalid hostnames', () => {
    expect(validateHostname('exam ple.com')).toBe('Invalid hostname');
    expect(validateHostname('-example.com')).toBe('Invalid hostname');
    expect(validateHostname('example-.com')).toBe('Invalid hostname');
  });
});

// ---------------------------------------------------------------------------
// validateRouteForm
// ---------------------------------------------------------------------------

describe('validateRouteForm', () => {
  function makeForm(overrides: Partial<RouteFormState> = {}): RouteFormState {
    return { ...ROUTE_DEFAULTS, hostname: 'test.com', ...overrides };
  }

  it('returns empty string for valid form', () => {
    expect(validateRouteForm(makeForm())).toBe('');
  });

  it('returns error for empty hostname', () => {
    expect(validateRouteForm(makeForm({ hostname: '' }))).toBe('Hostname is required');
  });

  it('returns error for invalid path prefix', () => {
    expect(validateRouteForm(makeForm({ path_prefix: 'no-slash' }))).toBe('Path prefix must start with /');
  });

  it('returns error for connect timeout out of range', () => {
    expect(validateRouteForm(makeForm({ connect_timeout_s: 0 }))).toContain('Connect timeout');
    expect(validateRouteForm(makeForm({ connect_timeout_s: 3601 }))).toContain('Connect timeout');
  });

  it('returns error for read timeout out of range', () => {
    expect(validateRouteForm(makeForm({ read_timeout_s: 0 }))).toContain('Read timeout');
  });

  it('returns error for send timeout out of range', () => {
    expect(validateRouteForm(makeForm({ send_timeout_s: 0 }))).toContain('Send timeout');
  });

  it('returns error for negative max body size', () => {
    expect(validateRouteForm(makeForm({ max_body_mb: '-1' }))).toContain('Max body size');
  });

  it('returns error for negative rate limit RPS', () => {
    expect(validateRouteForm(makeForm({ rate_limit_rps: '-5' }))).toContain('Rate limit RPS');
  });

  it('returns error for negative rate limit burst', () => {
    expect(validateRouteForm(makeForm({ rate_limit_burst: '-1' }))).toContain('Rate limit burst');
  });

  it('returns error when burst < RPS', () => {
    const err = validateRouteForm(makeForm({ rate_limit_rps: '100', rate_limit_burst: '50' }));
    expect(err).toContain('burst must be >= RPS');
  });

  it('accepts burst equal to RPS', () => {
    expect(validateRouteForm(makeForm({ rate_limit_rps: '100', rate_limit_burst: '100' }))).toBe('');
  });

  it('returns error for invalid IP allowlist', () => {
    expect(validateRouteForm(makeForm({ ip_allowlist: 'not-an-ip' }))).toContain('IP allowlist');
  });

  it('returns error for invalid IP denylist', () => {
    expect(validateRouteForm(makeForm({ ip_denylist: 'bad' }))).toContain('IP denylist');
  });

  it('returns error for negative CORS max age', () => {
    expect(validateRouteForm(makeForm({ cors_max_age_s: '-1' }))).toContain('CORS max age');
  });

  it('passes valid IP lists', () => {
    expect(validateRouteForm(makeForm({ ip_allowlist: '10.0.0.0/8\n192.168.1.0/24' }))).toBe('');
    expect(validateRouteForm(makeForm({ ip_denylist: '::1' }))).toBe('');
  });
});

// ---------------------------------------------------------------------------
// routeToFormState
// ---------------------------------------------------------------------------

describe('routeToFormState', () => {
  const mockRoute: RouteResponse = {
    id: 'r1',
    hostname: 'app.example.com',
    path_prefix: '/api',
    backends: ['b1', 'b2'],
    certificate_id: 'cert-1',
    load_balancing: 'peak_ewma',
    waf_enabled: true,
    waf_mode: 'enforcement',
    enabled: true,
    force_https: true,
    redirect_hostname: 'www.example.com',
    redirect_to: null,
    hostname_aliases: ['alias.example.com'],
    websocket_enabled: false,
    access_log_enabled: true,
    compression_enabled: true,
    connect_timeout_s: 10,
    read_timeout_s: 30,
    send_timeout_s: 30,
    strip_path_prefix: '/api',
    add_path_prefix: '/v2',
    path_rewrite_pattern: null,
    path_rewrite_replacement: null,
    retry_attempts: 3,
    security_headers: 'strict',
    max_request_body_bytes: 10485760, // 10 MB
    rate_limit_rps: 100,
    rate_limit_burst: 200,
    ip_allowlist: ['10.0.0.0/8'],
    ip_denylist: [],
    proxy_headers: { 'X-Custom': 'value' },
    proxy_headers_remove: ['X-Remove'],
    response_headers: {},
    response_headers_remove: [],
    cors_allowed_origins: ['*'],
    cors_allowed_methods: ['GET', 'POST'],
    cors_max_age_s: 3600,
    cache_enabled: false,
    cache_ttl_s: 300,
    cache_max_bytes: 52428800,
    max_connections: 500,
    slowloris_threshold_ms: 5000,
    auto_ban_threshold: 10,
    auto_ban_duration_s: 7200,
    path_rules: [],
    return_status: null,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  };

  it('maps hostname and path_prefix', () => {
    const form = routeToFormState(mockRoute);
    expect(form.hostname).toBe('app.example.com');
    expect(form.path_prefix).toBe('/api');
  });

  it('maps backend_ids as a copy', () => {
    const form = routeToFormState(mockRoute);
    expect(form.backend_ids).toEqual(['b1', 'b2']);
    // Ensure it is a copy, not the same reference
    expect(form.backend_ids).not.toBe(mockRoute.backends);
  });

  it('maps certificate_id', () => {
    const form = routeToFormState(mockRoute);
    expect(form.certificate_id).toBe('cert-1');
  });

  it('maps null certificate_id to empty string', () => {
    const form = routeToFormState({ ...mockRoute, certificate_id: null });
    expect(form.certificate_id).toBe('');
  });

  it('converts max_request_body_bytes to MB', () => {
    const form = routeToFormState(mockRoute);
    expect(form.max_body_mb).toBe('10');
  });

  it('converts rate limits to strings', () => {
    const form = routeToFormState(mockRoute);
    expect(form.rate_limit_rps).toBe('100');
    expect(form.rate_limit_burst).toBe('200');
  });

  it('converts null rate limits to empty strings', () => {
    const form = routeToFormState({ ...mockRoute, rate_limit_rps: null, rate_limit_burst: null });
    expect(form.rate_limit_rps).toBe('');
    expect(form.rate_limit_burst).toBe('');
  });

  it('converts ip_allowlist to newline-separated text', () => {
    const form = routeToFormState(mockRoute);
    expect(form.ip_allowlist).toBe('10.0.0.0/8');
  });

  it('converts proxy_headers to key=value text', () => {
    const form = routeToFormState(mockRoute);
    expect(form.proxy_headers).toBe('X-Custom=value');
  });

  it('converts hostname_aliases to comma-separated text', () => {
    const form = routeToFormState(mockRoute);
    expect(form.hostname_aliases).toBe('alias.example.com');
  });

  it('converts cors fields', () => {
    const form = routeToFormState(mockRoute);
    expect(form.cors_allowed_origins).toBe('*');
    expect(form.cors_allowed_methods).toBe('GET, POST');
    expect(form.cors_max_age_s).toBe('3600');
  });

  it('converts cache_max_bytes to MB', () => {
    const form = routeToFormState(mockRoute);
    expect(form.cache_max_mb).toBe(50);
  });

  it('converts return_status null to empty string', () => {
    const form = routeToFormState(mockRoute);
    expect(form.return_status).toBe('');
  });
});

// ---------------------------------------------------------------------------
// formStateToCreateRequest
// ---------------------------------------------------------------------------

describe('formStateToCreateRequest', () => {
  it('sets hostname and path_prefix', () => {
    const form = { ...ROUTE_DEFAULTS, hostname: 'test.com', path_prefix: '/app' };
    const req = formStateToCreateRequest(form);
    expect(req.hostname).toBe('test.com');
    expect(req.path_prefix).toBe('/app');
  });

  it('defaults path_prefix to /', () => {
    const form = { ...ROUTE_DEFAULTS, hostname: 'test.com', path_prefix: '' };
    const req = formStateToCreateRequest(form);
    expect(req.path_prefix).toBe('/');
  });

  it('includes backend_ids when non-empty', () => {
    const form = { ...ROUTE_DEFAULTS, hostname: 'test.com', backend_ids: ['b1'] };
    const req = formStateToCreateRequest(form);
    expect(req.backend_ids).toEqual(['b1']);
  });

  it('excludes backend_ids when empty', () => {
    const form = { ...ROUTE_DEFAULTS, hostname: 'test.com', backend_ids: [] };
    const req = formStateToCreateRequest(form);
    expect(req.backend_ids).toBeUndefined();
  });

  it('includes certificate_id when set', () => {
    const form = { ...ROUTE_DEFAULTS, hostname: 'test.com', certificate_id: 'c1' };
    const req = formStateToCreateRequest(form);
    expect(req.certificate_id).toBe('c1');
  });

  it('excludes certificate_id when empty', () => {
    const form = { ...ROUTE_DEFAULTS, hostname: 'test.com', certificate_id: '' };
    const req = formStateToCreateRequest(form);
    expect(req.certificate_id).toBeUndefined();
  });

  it('converts rate limit strings to numbers', () => {
    const form = { ...ROUTE_DEFAULTS, hostname: 'test.com', rate_limit_rps: '100', rate_limit_burst: '200' };
    const req = formStateToCreateRequest(form);
    expect(req.rate_limit_rps).toBe(100);
    expect(req.rate_limit_burst).toBe(200);
  });

  it('converts max_body_mb to bytes', () => {
    const form = { ...ROUTE_DEFAULTS, hostname: 'test.com', max_body_mb: '10' };
    const req = formStateToCreateRequest(form);
    expect(req.max_request_body_bytes).toBe(10 * 1024 * 1024);
  });

  it('converts ip_allowlist from newline text to array', () => {
    const form = { ...ROUTE_DEFAULTS, hostname: 'test.com', ip_allowlist: '10.0.0.0/8\n192.168.0.0/16' };
    const req = formStateToCreateRequest(form);
    expect(req.ip_allowlist).toEqual(['10.0.0.0/8', '192.168.0.0/16']);
  });

  it('converts proxy_headers from text to record', () => {
    const form = { ...ROUTE_DEFAULTS, hostname: 'test.com', proxy_headers: 'X-Foo=bar\nX-Baz=qux' };
    const req = formStateToCreateRequest(form);
    expect(req.proxy_headers).toEqual({ 'X-Foo': 'bar', 'X-Baz': 'qux' });
  });

  it('converts cors_allowed_origins from CSV to array', () => {
    const form = { ...ROUTE_DEFAULTS, hostname: 'test.com', cors_allowed_origins: '*, https://example.com' };
    const req = formStateToCreateRequest(form);
    expect(req.cors_allowed_origins).toEqual(['*', 'https://example.com']);
  });
});

// ---------------------------------------------------------------------------
// getModifiedFields
// ---------------------------------------------------------------------------

describe('getModifiedFields', () => {
  it('returns empty set for defaults', () => {
    const modified = getModifiedFields({ ...ROUTE_DEFAULTS });
    expect(modified.size).toBe(0);
  });

  it('detects changed hostname', () => {
    const form = { ...ROUTE_DEFAULTS, hostname: 'changed.com' };
    const modified = getModifiedFields(form);
    expect(modified.has('hostname')).toBe(true);
  });

  it('detects changed boolean fields', () => {
    const form = { ...ROUTE_DEFAULTS, waf_enabled: true };
    const modified = getModifiedFields(form);
    expect(modified.has('waf_enabled')).toBe(true);
  });

  it('detects changed string fields', () => {
    const form = { ...ROUTE_DEFAULTS, rate_limit_rps: '50' };
    const modified = getModifiedFields(form);
    expect(modified.has('rate_limit_rps')).toBe(true);
  });

  it('detects non-empty path_rules', () => {
    const form = {
      ...ROUTE_DEFAULTS,
      path_rules: [{
        path: '/api',
        match_type: 'prefix',
        backend_ids: [],
        cache_enabled: null,
        cache_ttl_s: null,
        response_headers: '',
        response_headers_remove: '',
        rate_limit_rps: '',
        rate_limit_burst: '',
        redirect_to: '',
        return_status: '',
      }],
    };
    const modified = getModifiedFields(form);
    expect(modified.has('path_rules')).toBe(true);
  });

  it('detects changed array fields (backend_ids)', () => {
    const form = { ...ROUTE_DEFAULTS, backend_ids: ['b1'] };
    const modified = getModifiedFields(form);
    expect(modified.has('backend_ids')).toBe(true);
  });

  it('does not detect unchanged numeric fields', () => {
    const form = { ...ROUTE_DEFAULTS, connect_timeout_s: 5 }; // same as default
    const modified = getModifiedFields(form);
    expect(modified.has('connect_timeout_s')).toBe(false);
  });
});
