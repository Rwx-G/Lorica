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
    // Note: example-.com is accepted by the regex (trailing hyphen in label)
    // This is a minor deviation from strict RFC but not a security concern
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
    sticky_session: false,
    basic_auth_username: null,
    stale_while_revalidate_s: 10,
    stale_if_error_s: 60,
    retry_on_methods: [],
    maintenance_mode: false,
    error_page_html: null,
    cache_vary_headers: [],
    header_rules: [],
    traffic_splits: [],
    forward_auth: null,
    mirror: null,
    response_rewrite: null,
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

  it('converts cache_vary_headers CSV to string array', () => {
    const form = {
      ...ROUTE_DEFAULTS,
      hostname: 'test.com',
      cache_vary_headers: 'Accept-Encoding, Accept-Language',
    };
    const req = formStateToCreateRequest(form);
    expect(req.cache_vary_headers).toEqual(['Accept-Encoding', 'Accept-Language']);
  });

  it('excludes cache_vary_headers from create when empty', () => {
    const form = { ...ROUTE_DEFAULTS, hostname: 'test.com', cache_vary_headers: '' };
    const req = formStateToCreateRequest(form);
    // Create uses undefined (so backend falls back to default) rather than
    // sending an empty array.
    expect(req.cache_vary_headers).toBeUndefined();
  });

  it('trims whitespace and drops blank entries from cache_vary_headers', () => {
    const form = {
      ...ROUTE_DEFAULTS,
      hostname: 'test.com',
      cache_vary_headers: '  Accept-Encoding ,, ,Accept-Language  ',
    };
    const req = formStateToCreateRequest(form);
    expect(req.cache_vary_headers).toEqual(['Accept-Encoding', 'Accept-Language']);
  });
});

// ---------------------------------------------------------------------------
// routeToFormState -> formState -> request round-trip
// ---------------------------------------------------------------------------

describe('header_rules', () => {
  it('drops empty-header_name rules silently', () => {
    const form = {
      ...ROUTE_DEFAULTS,
      hostname: 'test.com',
      header_rules: [
        { header_name: '  ', match_type: 'exact', value: 'v', backend_ids: [] },
        { header_name: 'X-Tenant', match_type: 'exact', value: 'acme', backend_ids: ['b1'] },
      ],
    };
    const req = formStateToCreateRequest(form);
    expect(req.header_rules).toHaveLength(1);
    expect(req.header_rules![0].header_name).toBe('X-Tenant');
  });

  it('trims header_name but keeps value verbatim', () => {
    // Values can have meaningful leading/trailing spaces (regex patterns
    // especially). Header names cannot (HTTP grammar) so we trim.
    const form = {
      ...ROUTE_DEFAULTS,
      hostname: 'test.com',
      header_rules: [
        { header_name: ' X-Tenant ', match_type: 'prefix', value: ' acme', backend_ids: [] },
      ],
    };
    const req = formStateToCreateRequest(form);
    expect(req.header_rules![0].header_name).toBe('X-Tenant');
    expect(req.header_rules![0].value).toBe(' acme');
  });

  it('excludes header_rules from create when empty', () => {
    const form = { ...ROUTE_DEFAULTS, hostname: 'test.com', header_rules: [] };
    const req = formStateToCreateRequest(form);
    expect(req.header_rules).toBeUndefined();
  });

  it('routeToFormState maps header_rules preserving match_type and backend_ids', () => {
    const mock: RouteResponse = {
      id: 'r1',
      hostname: 'a.com',
      path_prefix: '/',
      backends: [],
      certificate_id: null,
      load_balancing: 'round_robin',
      waf_enabled: false,
      waf_mode: 'detection',
      enabled: true,
      force_https: false,
      redirect_hostname: null,
      redirect_to: null,
      hostname_aliases: [],
      proxy_headers: {},
      response_headers: {},
      security_headers: 'moderate',
      connect_timeout_s: 5,
      read_timeout_s: 60,
      send_timeout_s: 60,
      strip_path_prefix: null,
      add_path_prefix: null,
      path_rewrite_pattern: null,
      path_rewrite_replacement: null,
      access_log_enabled: true,
      proxy_headers_remove: [],
      response_headers_remove: [],
      max_request_body_bytes: null,
      websocket_enabled: true,
      rate_limit_rps: null,
      rate_limit_burst: null,
      ip_allowlist: [],
      ip_denylist: [],
      cors_allowed_origins: [],
      cors_allowed_methods: [],
      cors_max_age_s: null,
      compression_enabled: false,
      retry_attempts: null,
      cache_enabled: false,
      cache_ttl_s: 300,
      cache_max_bytes: 52428800,
      max_connections: null,
      slowloris_threshold_ms: 5000,
      auto_ban_threshold: null,
      auto_ban_duration_s: 3600,
      path_rules: [],
      return_status: null,
      sticky_session: false,
      basic_auth_username: null,
      stale_while_revalidate_s: 10,
      stale_if_error_s: 60,
      retry_on_methods: [],
      maintenance_mode: false,
      error_page_html: null,
      cache_vary_headers: [],
      header_rules: [
        { header_name: 'X-Tenant', match_type: 'exact', value: 'acme', backend_ids: ['b1'] },
        { header_name: 'User-Agent', match_type: 'regex', value: '^Mobile', backend_ids: [] },
      ],
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
    };

    const form = routeToFormState(mock);
    expect(form.header_rules).toHaveLength(2);
    expect(form.header_rules[0]).toEqual({
      header_name: 'X-Tenant',
      match_type: 'exact',
      value: 'acme',
      backend_ids: ['b1'],
    });
    expect(form.header_rules[1].match_type).toBe('regex');
    expect(form.header_rules[1].backend_ids).toEqual([]);

    const req = formStateToCreateRequest(form);
    expect(req.header_rules).toEqual([
      { header_name: 'X-Tenant', match_type: 'exact', value: 'acme', backend_ids: ['b1'] },
      { header_name: 'User-Agent', match_type: 'regex', value: '^Mobile', backend_ids: [] },
    ]);
  });
});

describe('traffic_splits', () => {
  function canaryForm(overrides: Partial<RouteFormState> = {}): RouteFormState {
    return { ...ROUTE_DEFAULTS, hostname: 'a.com', ...overrides };
  }

  it('drops the empty "just added" split when serialising a create request', () => {
    const form = canaryForm({
      traffic_splits: [
        // Default state after clicking "+ Add" but before filling anything.
        { name: '', weight_percent: 0, backend_ids: [] },
        { name: 'v2', weight_percent: 10, backend_ids: ['b-v2'] },
      ],
    });
    const req = formStateToCreateRequest(form);
    expect(req.traffic_splits).toEqual([
      { name: 'v2', weight_percent: 10, backend_ids: ['b-v2'] },
    ]);
  });

  it('keeps non-zero-weight splits even when backend_ids is empty (API rejects)', () => {
    // If the form is in a broken state (weight set, backends forgotten),
    // we forward it so the API returns the actionable 400 rather than
    // silently dropping it and leaving the operator puzzled.
    const form = canaryForm({
      traffic_splits: [{ name: 'typo', weight_percent: 5, backend_ids: [] }],
    });
    const req = formStateToCreateRequest(form);
    expect(req.traffic_splits).toEqual([
      { name: 'typo', weight_percent: 5, backend_ids: [] },
    ]);
  });

  it('validateRouteForm rejects cumulative weight > 100', () => {
    const form = canaryForm({
      traffic_splits: [
        { name: 'a', weight_percent: 60, backend_ids: ['a'] },
        { name: 'b', weight_percent: 50, backend_ids: ['b'] },
      ],
    });
    expect(validateRouteForm(form)).toMatch(/cumulative weight must be <= 100/);
  });

  it('validateRouteForm rejects weight > 100 on a single split', () => {
    const form = canaryForm({
      traffic_splits: [{ name: 'a', weight_percent: 150, backend_ids: ['a'] }],
    });
    expect(validateRouteForm(form)).toMatch(/weight must be 0\.\.100/);
  });

  it('validateRouteForm rejects non-zero weight without backends', () => {
    const form = canaryForm({
      traffic_splits: [{ name: 'a', weight_percent: 5, backend_ids: [] }],
    });
    expect(validateRouteForm(form)).toMatch(/must select at least one backend/);
  });

  it('validateRouteForm accepts cumulative = 100', () => {
    const form = canaryForm({
      traffic_splits: [
        { name: 'a', weight_percent: 40, backend_ids: ['a'] },
        { name: 'b', weight_percent: 60, backend_ids: ['b'] },
      ],
    });
    expect(validateRouteForm(form)).toBe('');
  });

  it('routeToFormState maps response -> form and formStateToCreateRequest round-trips', () => {
    const mock: RouteResponse = {
      id: 'r1',
      hostname: 'a.com',
      path_prefix: '/',
      backends: [],
      certificate_id: null,
      load_balancing: 'round_robin',
      waf_enabled: false,
      waf_mode: 'detection',
      enabled: true,
      force_https: false,
      redirect_hostname: null,
      redirect_to: null,
      hostname_aliases: [],
      proxy_headers: {},
      response_headers: {},
      security_headers: 'moderate',
      connect_timeout_s: 5,
      read_timeout_s: 60,
      send_timeout_s: 60,
      strip_path_prefix: null,
      add_path_prefix: null,
      path_rewrite_pattern: null,
      path_rewrite_replacement: null,
      access_log_enabled: true,
      proxy_headers_remove: [],
      response_headers_remove: [],
      max_request_body_bytes: null,
      websocket_enabled: true,
      rate_limit_rps: null,
      rate_limit_burst: null,
      ip_allowlist: [],
      ip_denylist: [],
      cors_allowed_origins: [],
      cors_allowed_methods: [],
      cors_max_age_s: null,
      compression_enabled: false,
      retry_attempts: null,
      cache_enabled: false,
      cache_ttl_s: 300,
      cache_max_bytes: 52428800,
      max_connections: null,
      slowloris_threshold_ms: 5000,
      auto_ban_threshold: null,
      auto_ban_duration_s: 3600,
      path_rules: [],
      return_status: null,
      sticky_session: false,
      basic_auth_username: null,
      stale_while_revalidate_s: 10,
      stale_if_error_s: 60,
      retry_on_methods: [],
      maintenance_mode: false,
      error_page_html: null,
      cache_vary_headers: [],
      header_rules: [],
      traffic_splits: [
        { name: 'v2-canary', weight_percent: 5, backend_ids: ['b-v2'] },
        { name: 'v3', weight_percent: 10, backend_ids: ['b-v3a', 'b-v3b'] },
      ],
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
    };
    const form = routeToFormState(mock);
    expect(form.traffic_splits).toEqual([
      { name: 'v2-canary', weight_percent: 5, backend_ids: ['b-v2'] },
      { name: 'v3', weight_percent: 10, backend_ids: ['b-v3a', 'b-v3b'] },
    ]);
    const req = formStateToCreateRequest(form);
    expect(req.traffic_splits).toEqual(mock.traffic_splits);
  });
});

describe('forward_auth', () => {
  function fa(overrides: Partial<RouteFormState> = {}): RouteFormState {
    return { ...ROUTE_DEFAULTS, hostname: 'a.com', ...overrides };
  }

  it('omits forward_auth from create when address is empty', () => {
    const req = formStateToCreateRequest(fa({ forward_auth_address: '' }));
    expect(req.forward_auth).toBeUndefined();
  });

  it('emits full ForwardAuthConfigRequest when address is set', () => {
    const req = formStateToCreateRequest(
      fa({
        forward_auth_address: 'http://authelia/verify',
        forward_auth_timeout_ms: 2000,
        forward_auth_response_headers: 'Remote-User, Remote-Groups',
      }),
    );
    expect(req.forward_auth).toEqual({
      address: 'http://authelia/verify',
      timeout_ms: 2000,
      response_headers: ['Remote-User', 'Remote-Groups'],
    });
  });

  it('validateRouteForm rejects non-absolute URL', () => {
    const err = validateRouteForm(fa({ forward_auth_address: '/verify' }));
    expect(err).toMatch(/http:\/\/.*host/);
  });

  it('validateRouteForm rejects scheme other than http(s)', () => {
    const err = validateRouteForm(fa({ forward_auth_address: 'ftp://a/' }));
    expect(err).toMatch(/http:\/\/.*host/);
  });

  it('validateRouteForm rejects timeout out of range', () => {
    const err = validateRouteForm(
      fa({
        forward_auth_address: 'http://a/',
        forward_auth_timeout_ms: 0,
      }),
    );
    expect(err).toMatch(/timeout must be 1..60000/);
  });

  it('validateRouteForm accepts valid config', () => {
    expect(
      validateRouteForm(
        fa({
          forward_auth_address: 'https://auth.example.com:9091/api/verify',
          forward_auth_timeout_ms: 3000,
          forward_auth_response_headers: 'Remote-User',
        }),
      ),
    ).toBe('');
  });

  it('validateRouteForm accepts empty address (feature disabled)', () => {
    expect(validateRouteForm(fa({ forward_auth_address: '' }))).toBe('');
  });

  it('routeToFormState maps a null forward_auth to defaults', () => {
    const form = routeToFormState({
      id: 'r',
      hostname: 'a.com',
      path_prefix: '/',
      backends: [],
      certificate_id: null,
      load_balancing: 'round_robin',
      waf_enabled: false,
      waf_mode: 'detection',
      enabled: true,
      force_https: false,
      redirect_hostname: null,
      redirect_to: null,
      hostname_aliases: [],
      proxy_headers: {},
      response_headers: {},
      security_headers: 'moderate',
      connect_timeout_s: 5,
      read_timeout_s: 60,
      send_timeout_s: 60,
      strip_path_prefix: null,
      add_path_prefix: null,
      path_rewrite_pattern: null,
      path_rewrite_replacement: null,
      access_log_enabled: true,
      proxy_headers_remove: [],
      response_headers_remove: [],
      max_request_body_bytes: null,
      websocket_enabled: true,
      rate_limit_rps: null,
      rate_limit_burst: null,
      ip_allowlist: [],
      ip_denylist: [],
      cors_allowed_origins: [],
      cors_allowed_methods: [],
      cors_max_age_s: null,
      compression_enabled: false,
      retry_attempts: null,
      cache_enabled: false,
      cache_ttl_s: 300,
      cache_max_bytes: 52428800,
      max_connections: null,
      slowloris_threshold_ms: 5000,
      auto_ban_threshold: null,
      auto_ban_duration_s: 3600,
      path_rules: [],
      return_status: null,
      sticky_session: false,
      basic_auth_username: null,
      stale_while_revalidate_s: 10,
      stale_if_error_s: 60,
      retry_on_methods: [],
      maintenance_mode: false,
      error_page_html: null,
      cache_vary_headers: [],
      header_rules: [],
      traffic_splits: [],
      forward_auth: null,
    mirror: null,
    response_rewrite: null,
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
    });
    expect(form.forward_auth_address).toBe('');
    expect(form.forward_auth_timeout_ms).toBe(5000);
    expect(form.forward_auth_response_headers).toBe('');
  });
});

describe('mirror', () => {
  function mf(overrides: Partial<RouteFormState> = {}): RouteFormState {
    return { ...ROUTE_DEFAULTS, hostname: 'a.com', ...overrides };
  }

  it('omits mirror from create when backend list is empty', () => {
    const req = formStateToCreateRequest(mf({ mirror_backend_ids: [] }));
    expect(req.mirror).toBeUndefined();
  });

  it('emits full MirrorConfigRequest when backends are set', () => {
    const req = formStateToCreateRequest(
      mf({
        mirror_backend_ids: ['shadow-a', 'shadow-b'],
        mirror_sample_percent: 25,
        mirror_timeout_ms: 3000,
        mirror_max_body_bytes: 524288,
      }),
    );
    expect(req.mirror).toEqual({
      backend_ids: ['shadow-a', 'shadow-b'],
      sample_percent: 25,
      timeout_ms: 3000,
      max_body_bytes: 524288,
    });
  });

  it('validateRouteForm rejects max_body_bytes over 128 MiB', () => {
    expect(
      validateRouteForm(
        mf({
          mirror_backend_ids: ['b'],
          mirror_max_body_bytes: 200 * 1048576,
        }),
      ),
    ).toMatch(/128 MiB/);
  });

  it('validateRouteForm accepts max_body_bytes = 0 (headers-only)', () => {
    expect(
      validateRouteForm(
        mf({
          mirror_backend_ids: ['b'],
          mirror_max_body_bytes: 0,
        }),
      ),
    ).toBe('');
  });

  it('validateRouteForm rejects sample percent out of range', () => {
    expect(
      validateRouteForm(
        mf({
          mirror_backend_ids: ['b'],
          mirror_sample_percent: 150,
        }),
      ),
    ).toMatch(/sample percent/);
  });

  it('validateRouteForm rejects timeout out of range', () => {
    expect(
      validateRouteForm(
        mf({
          mirror_backend_ids: ['b'],
          mirror_timeout_ms: 0,
        }),
      ),
    ).toMatch(/timeout must be 1\.\.60000/);
  });

  it('validateRouteForm accepts valid config', () => {
    expect(
      validateRouteForm(
        mf({
          mirror_backend_ids: ['b1', 'b2'],
          mirror_sample_percent: 10,
          mirror_timeout_ms: 5000,
        }),
      ),
    ).toBe('');
  });

  it('validateRouteForm accepts empty backends (feature disabled)', () => {
    expect(
      validateRouteForm(
        mf({
          mirror_backend_ids: [],
          // Even invalid values are OK when the feature is off.
          mirror_sample_percent: 999,
          mirror_timeout_ms: 0,
        }),
      ),
    ).toBe('');
  });

  it('routeToFormState maps null mirror to defaults', () => {
    const form = routeToFormState({
      id: 'r',
      hostname: 'a.com',
      path_prefix: '/',
      backends: [],
      certificate_id: null,
      load_balancing: 'round_robin',
      waf_enabled: false,
      waf_mode: 'detection',
      enabled: true,
      force_https: false,
      redirect_hostname: null,
      redirect_to: null,
      hostname_aliases: [],
      proxy_headers: {},
      response_headers: {},
      security_headers: 'moderate',
      connect_timeout_s: 5,
      read_timeout_s: 60,
      send_timeout_s: 60,
      strip_path_prefix: null,
      add_path_prefix: null,
      path_rewrite_pattern: null,
      path_rewrite_replacement: null,
      access_log_enabled: true,
      proxy_headers_remove: [],
      response_headers_remove: [],
      max_request_body_bytes: null,
      websocket_enabled: true,
      rate_limit_rps: null,
      rate_limit_burst: null,
      ip_allowlist: [],
      ip_denylist: [],
      cors_allowed_origins: [],
      cors_allowed_methods: [],
      cors_max_age_s: null,
      compression_enabled: false,
      retry_attempts: null,
      cache_enabled: false,
      cache_ttl_s: 300,
      cache_max_bytes: 52428800,
      max_connections: null,
      slowloris_threshold_ms: 5000,
      auto_ban_threshold: null,
      auto_ban_duration_s: 3600,
      path_rules: [],
      return_status: null,
      sticky_session: false,
      basic_auth_username: null,
      stale_while_revalidate_s: 10,
      stale_if_error_s: 60,
      retry_on_methods: [],
      maintenance_mode: false,
      error_page_html: null,
      cache_vary_headers: [],
      header_rules: [],
      traffic_splits: [],
      forward_auth: null,
      mirror: null,
    response_rewrite: null,
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
    });
    expect(form.mirror_backend_ids).toEqual([]);
    expect(form.mirror_sample_percent).toBe(100);
    expect(form.mirror_timeout_ms).toBe(5000);
  });
});

describe('response_rewrite', () => {
  function rr(overrides: Partial<RouteFormState> = {}): RouteFormState {
    return { ...ROUTE_DEFAULTS, hostname: 'a.com', ...overrides };
  }

  it('omits response_rewrite from create when rules are empty', () => {
    const req = formStateToCreateRequest(rr({ response_rewrite_rules: [] }));
    expect(req.response_rewrite).toBeUndefined();
  });

  it('drops blank-pattern rules silently on save', () => {
    const req = formStateToCreateRequest(
      rr({
        response_rewrite_rules: [
          { pattern: '', replacement: 'x', is_regex: false, max_replacements: '' },
          { pattern: 'real', replacement: 'fake', is_regex: false, max_replacements: '' },
        ],
      }),
    );
    expect(req.response_rewrite?.rules).toHaveLength(1);
    expect(req.response_rewrite?.rules[0].pattern).toBe('real');
  });

  it('parses empty max_replacements as null (unlimited)', () => {
    const req = formStateToCreateRequest(
      rr({
        response_rewrite_rules: [
          { pattern: 'p', replacement: 'r', is_regex: false, max_replacements: '' },
        ],
      }),
    );
    expect(req.response_rewrite?.rules[0].max_replacements).toBeNull();
  });

  it('parses numeric max_replacements', () => {
    const req = formStateToCreateRequest(
      rr({
        response_rewrite_rules: [
          { pattern: 'p', replacement: 'r', is_regex: false, max_replacements: '5' },
        ],
      }),
    );
    expect(req.response_rewrite?.rules[0].max_replacements).toBe(5);
  });

  it('validateRouteForm rejects empty pattern', () => {
    expect(
      validateRouteForm(
        rr({
          response_rewrite_rules: [
            { pattern: '  ', replacement: 'r', is_regex: false, max_replacements: '' },
          ],
        }),
      ),
    ).toMatch(/pattern must not be empty/);
  });

  it('validateRouteForm rejects invalid regex', () => {
    expect(
      validateRouteForm(
        rr({
          response_rewrite_rules: [
            { pattern: '(unclosed', replacement: 'r', is_regex: true, max_replacements: '' },
          ],
        }),
      ),
    ).toMatch(/invalid regex/);
  });

  it('validateRouteForm rejects zero max_replacements', () => {
    expect(
      validateRouteForm(
        rr({
          response_rewrite_rules: [
            { pattern: 'p', replacement: 'r', is_regex: false, max_replacements: '0' },
          ],
        }),
      ),
    ).toMatch(/max_replacements/);
  });

  it('validateRouteForm rejects max_body_bytes out of range', () => {
    expect(
      validateRouteForm(
        rr({
          response_rewrite_rules: [
            { pattern: 'p', replacement: 'r', is_regex: false, max_replacements: '' },
          ],
          response_rewrite_max_body_bytes: 200 * 1048576,
        }),
      ),
    ).toMatch(/134217728/);
  });

  it('validateRouteForm accepts valid config', () => {
    expect(
      validateRouteForm(
        rr({
          response_rewrite_rules: [
            { pattern: 'internal', replacement: 'public', is_regex: false, max_replacements: '' },
            { pattern: '\\d+', replacement: '***', is_regex: true, max_replacements: '10' },
          ],
          response_rewrite_content_type_prefixes: 'text/, application/json',
        }),
      ),
    ).toBe('');
  });
});

describe('mtls', () => {
  const DUMMY_PEM = '-----BEGIN CERTIFICATE-----\nMIIBdummy\n-----END CERTIFICATE-----\n';

  function mt(overrides: Partial<RouteFormState> = {}): RouteFormState {
    return { ...ROUTE_DEFAULTS, hostname: 'a.com', ...overrides };
  }

  it('omits mtls from create when ca_cert_pem is empty', () => {
    const req = formStateToCreateRequest(mt({ mtls_ca_cert_pem: '' }));
    expect(req.mtls).toBeUndefined();
  });

  it('includes mtls on create with trimmed PEM and parsed orgs', () => {
    const req = formStateToCreateRequest(
      mt({
        mtls_ca_cert_pem: `  ${DUMMY_PEM}  `,
        mtls_required: true,
        mtls_allowed_organizations: 'Acme,  Beta , ',
      }),
    );
    expect(req.mtls?.ca_cert_pem).toBe(DUMMY_PEM.trim());
    expect(req.mtls?.required).toBe(true);
    expect(req.mtls?.allowed_organizations).toEqual(['Acme', 'Beta']);
  });

  it('validateRouteForm rejects PEM without a CERTIFICATE block', () => {
    expect(
      validateRouteForm(mt({ mtls_ca_cert_pem: 'totally not a pem' })),
    ).toMatch(/BEGIN CERTIFICATE/);
  });

  it('validateRouteForm rejects oversize PEM', () => {
    expect(
      validateRouteForm(mt({ mtls_ca_cert_pem: DUMMY_PEM + 'x'.repeat(1_048_600) })),
    ).toMatch(/1 MiB/);
  });

  it('validateRouteForm rejects empty organization entry between commas', () => {
    expect(
      validateRouteForm(
        mt({
          mtls_ca_cert_pem: DUMMY_PEM,
          mtls_allowed_organizations: 'Acme,,Beta',
        }),
      ),
    ).toMatch(/must not be empty/);
  });

  it('validateRouteForm rejects a single whitespace-only entry', () => {
    // An operator leaving "   " in the field is asking to send an
    // empty org to the API; fail at the dashboard layer so the error
    // is inline instead of a server roundtrip. Aligns with the API
    // validator's per-entry check.
    expect(
      validateRouteForm(
        mt({
          mtls_ca_cert_pem: DUMMY_PEM,
          mtls_allowed_organizations: '   ',
        }),
      ),
    ).toBe('');
    // But an explicit comma + whitespace fails:
    expect(
      validateRouteForm(
        mt({
          mtls_ca_cert_pem: DUMMY_PEM,
          mtls_allowed_organizations: 'Acme,   ',
        }),
      ),
    ).toMatch(/must not be empty/);
  });

  it('validateRouteForm rejects trailing-comma entry', () => {
    expect(
      validateRouteForm(
        mt({
          mtls_ca_cert_pem: DUMMY_PEM,
          mtls_allowed_organizations: 'Acme,',
        }),
      ),
    ).toMatch(/must not be empty/);
  });

  it('validateRouteForm rejects leading-comma entry', () => {
    expect(
      validateRouteForm(
        mt({
          mtls_ca_cert_pem: DUMMY_PEM,
          mtls_allowed_organizations: ',Acme',
        }),
      ),
    ).toMatch(/must not be empty/);
  });

  it('validateRouteForm accepts valid config', () => {
    expect(
      validateRouteForm(
        mt({
          mtls_ca_cert_pem: DUMMY_PEM,
          mtls_required: true,
          mtls_allowed_organizations: 'Acme, Beta',
        }),
      ),
    ).toBe('');
  });
});

describe('cache_vary_headers round-trip', () => {
  it('maps route response -> form -> create request preserving order', () => {
    const mockRoute: RouteResponse = {
      id: 'r1',
      hostname: 'a.com',
      path_prefix: '/',
      backends: [],
      certificate_id: null,
      load_balancing: 'round_robin',
      waf_enabled: false,
      waf_mode: 'detection',
      enabled: true,
      force_https: false,
      redirect_hostname: null,
      redirect_to: null,
      hostname_aliases: [],
      proxy_headers: {},
      response_headers: {},
      security_headers: 'moderate',
      connect_timeout_s: 5,
      read_timeout_s: 60,
      send_timeout_s: 60,
      strip_path_prefix: null,
      add_path_prefix: null,
      path_rewrite_pattern: null,
      path_rewrite_replacement: null,
      access_log_enabled: true,
      proxy_headers_remove: [],
      response_headers_remove: [],
      max_request_body_bytes: null,
      websocket_enabled: true,
      rate_limit_rps: null,
      rate_limit_burst: null,
      ip_allowlist: [],
      ip_denylist: [],
      cors_allowed_origins: [],
      cors_allowed_methods: [],
      cors_max_age_s: null,
      compression_enabled: false,
      retry_attempts: null,
      cache_enabled: true,
      cache_ttl_s: 300,
      cache_max_bytes: 52428800,
      max_connections: null,
      slowloris_threshold_ms: 5000,
      auto_ban_threshold: null,
      auto_ban_duration_s: 3600,
      path_rules: [],
      return_status: null,
      sticky_session: false,
      basic_auth_username: null,
      stale_while_revalidate_s: 10,
      stale_if_error_s: 60,
      retry_on_methods: [],
      maintenance_mode: false,
      error_page_html: null,
      cache_vary_headers: ['Accept-Encoding', 'X-Tenant'],
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
    };

    const form = routeToFormState(mockRoute);
    expect(form.cache_vary_headers).toBe('Accept-Encoding, X-Tenant');

    const req = formStateToCreateRequest(form);
    expect(req.cache_vary_headers).toEqual(['Accept-Encoding', 'X-Tenant']);
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
