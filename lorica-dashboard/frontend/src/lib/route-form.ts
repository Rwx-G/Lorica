import type { RouteResponse, CreateRouteRequest, UpdateRouteRequest, PathRuleRequest, HeaderRuleRequest, TrafficSplitRequest, ForwardAuthConfigRequest, MirrorConfigRequest, ResponseRewriteConfigRequest, MtlsConfigRequest } from './api';

export interface PathRuleFormState {
  path: string;
  match_type: string;
  backend_ids: string[];
  cache_enabled: boolean | null;
  cache_ttl_s: number | null;
  response_headers: string;
  response_headers_remove: string;
  rate_limit_rps: string;
  rate_limit_burst: string;
  redirect_to: string;
  return_status: string;
}

export interface HeaderRuleFormState {
  header_name: string;
  match_type: string;   // 'exact' | 'prefix' | 'regex'
  value: string;
  backend_ids: string[];
  // Read-only runtime signal from the server: true when the proxy
  // skipped the rule because its regex failed to compile. The form
  // never sends this back; we only use it to render a warning badge.
  disabled?: boolean;
}

export interface TrafficSplitFormState {
  name: string;
  weight_percent: number;
  backend_ids: string[];
}

export interface ResponseRewriteRuleFormState {
  pattern: string;
  replacement: string;
  is_regex: boolean;
  max_replacements: string; // "" = unlimited; otherwise parseable int
}

export interface RouteFormState {
  hostname: string;
  path_prefix: string;
  backend_ids: string[];
  certificate_id: string;
  load_balancing: string;
  waf_enabled: boolean;
  waf_mode: string;
  enabled: boolean;
  force_https: boolean;
  redirect_hostname: string;
  redirect_to: string;
  hostname_aliases: string;
  websocket_enabled: boolean;
  access_log_enabled: boolean;
  compression_enabled: boolean;
  connect_timeout_s: number;
  read_timeout_s: number;
  send_timeout_s: number;
  strip_path_prefix: string;
  add_path_prefix: string;
  path_rewrite_pattern: string;
  path_rewrite_replacement: string;
  retry_attempts: string;
  security_headers: string;
  max_body_mb: string;
  rate_limit_rps: string;
  rate_limit_burst: string;
  ip_allowlist: string;
  ip_denylist: string;
  proxy_headers: string;
  proxy_headers_remove: string;
  response_headers: string;
  response_headers_remove: string;
  cors_allowed_origins: string;
  cors_allowed_methods: string;
  cors_max_age_s: string;
  cache_enabled: boolean;
  cache_ttl_s: number;
  cache_max_mb: number;
  max_connections: string;
  slowloris_threshold_ms: number;
  auto_ban_threshold: string;
  auto_ban_duration_s: number;
  path_rules: PathRuleFormState[];
  return_status: string;
  sticky_session: boolean;
  basic_auth_username: string;
  basic_auth_password: string;
  stale_while_revalidate_s: number;
  stale_if_error_s: number;
  retry_on_methods: string;
  error_page_html: string;
  cache_vary_headers: string;
  header_rules: HeaderRuleFormState[];
  traffic_splits: TrafficSplitFormState[];
  forward_auth_address: string;        // empty = feature off
  forward_auth_timeout_ms: number;     // 5000 default
  forward_auth_response_headers: string; // CSV
  mirror_backend_ids: string[];         // empty = feature off
  mirror_sample_percent: number;        // 0..100
  mirror_timeout_ms: number;            // 5000 default
  mirror_max_body_bytes: number;        // 1048576 default; 0 = headers-only
  response_rewrite_rules: ResponseRewriteRuleFormState[]; // empty = feature off
  response_rewrite_max_body_bytes: number;
  response_rewrite_content_type_prefixes: string; // CSV
  mtls_ca_cert_pem: string;              // empty = feature off
  mtls_required: boolean;
  mtls_allowed_organizations: string;    // CSV
  // Per-route token-bucket rate limit (cross-worker under `--workers`).
  // Empty / 0 capacity = feature off.
  rate_limit_capacity: number | '';
  rate_limit_refill_per_sec: number | '';
  rate_limit_scope: 'per_ip' | 'per_route';
  // GeoIP country filter (v1.4.0 Epic 2). Empty countries = feature
  // off in denylist mode; allowlist mode requires at least one
  // country (API rejects empty allowlist at write time). Countries
  // are ISO 3166-1 alpha-2 comma-separated (e.g. "FR,DE,IT").
  geoip_mode: 'allowlist' | 'denylist';
  geoip_countries: string;
  // Bot protection (v1.4.0 Epic 3). `bot_enabled = false` means
  // the feature is off for this route; the other fields are
  // persisted regardless so toggling the switch does not lose
  // configured values. Bypass user-agent patterns are
  // newline-separated (one regex per line) because commas may
  // legitimately appear inside a regex and would be a UX trap
  // with CSV. `bot_only_country` empty = challenge applies to
  // every request (bypass rules are the only escape hatch).
  bot_enabled: boolean;
  bot_mode: 'cookie' | 'javascript' | 'captcha';
  bot_cookie_ttl_s: number;
  bot_pow_difficulty: number;
  bot_captcha_alphabet: string;
  bot_bypass_ip_cidrs: string;
  bot_bypass_asns: string;
  bot_bypass_countries: string;
  bot_bypass_user_agents: string;
  bot_bypass_rdns: string;
  bot_only_country: string;
}

export const ROUTE_DEFAULTS: RouteFormState = {
  hostname: '',
  path_prefix: '/',
  backend_ids: [],
  certificate_id: '',
  load_balancing: 'round_robin',
  waf_enabled: false,
  waf_mode: 'detection',
  enabled: true,
  force_https: false,
  redirect_hostname: '',
  redirect_to: '',
  hostname_aliases: '',
  websocket_enabled: true,
  access_log_enabled: true,
  compression_enabled: false,
  connect_timeout_s: 5,
  read_timeout_s: 60,
  send_timeout_s: 60,
  strip_path_prefix: '',
  add_path_prefix: '',
  path_rewrite_pattern: '',
  path_rewrite_replacement: '',
  retry_attempts: '',
  security_headers: 'moderate',
  max_body_mb: '',
  rate_limit_rps: '',
  rate_limit_burst: '',
  ip_allowlist: '',
  ip_denylist: '',
  proxy_headers: '',
  proxy_headers_remove: '',
  response_headers: '',
  response_headers_remove: '',
  cors_allowed_origins: '',
  cors_allowed_methods: '',
  cors_max_age_s: '',
  cache_enabled: false,
  cache_ttl_s: 300,
  cache_max_mb: 50,
  max_connections: '',
  slowloris_threshold_ms: 5000,
  auto_ban_threshold: '',
  auto_ban_duration_s: 3600,
  path_rules: [],
  return_status: '',
  sticky_session: false,
  basic_auth_username: '',
  basic_auth_password: '',
  stale_while_revalidate_s: 10,
  stale_if_error_s: 60,
  retry_on_methods: '',
  error_page_html: '',
  cache_vary_headers: '',
  header_rules: [],
  traffic_splits: [],
  forward_auth_address: '',
  forward_auth_timeout_ms: 5000,
  forward_auth_response_headers: '',
  mirror_backend_ids: [],
  mirror_sample_percent: 100,
  mirror_timeout_ms: 5000,
  mirror_max_body_bytes: 1048576,
  response_rewrite_rules: [],
  response_rewrite_max_body_bytes: 1048576,
  response_rewrite_content_type_prefixes: '',
  mtls_ca_cert_pem: '',
  mtls_required: false,
  mtls_allowed_organizations: '',
  rate_limit_capacity: '',
  rate_limit_refill_per_sec: '',
  rate_limit_scope: 'per_ip',
  geoip_mode: 'denylist',
  geoip_countries: '',
  bot_enabled: false,
  bot_mode: 'javascript',
  bot_cookie_ttl_s: 86400,
  bot_pow_difficulty: 18,
  bot_captcha_alphabet:
    '23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ',
  bot_bypass_ip_cidrs: '',
  bot_bypass_asns: '',
  bot_bypass_countries: '',
  bot_bypass_user_agents: '',
  bot_bypass_rdns: '',
  bot_only_country: '',
};

// Tab field mappings for dot indicators
export const TAB_FIELDS: Record<string, (keyof RouteFormState)[]> = {
  general: [
    // Identity + Response override only (v1.4.0 UX refactor pass 1).
    'hostname', 'path_prefix', 'hostname_aliases',
    'websocket_enabled', 'access_log_enabled',
    'redirect_to', 'redirect_hostname', 'return_status', 'error_page_html',
  ],
  routing: [
    // Default backends
    'backend_ids', 'certificate_id', 'load_balancing', 'force_https', 'sticky_session',
    // Traffic splits (absorbed from former Canary tab)
    'traffic_splits',
    // Header-based routes (absorbed from former Header Rules tab)
    'header_rules',
    // Path-based overrides (absorbed from former Path Rules tab)
    'path_rules',
    // Shadow / Mirror (absorbed from the Security tab)
    'mirror_backend_ids', 'mirror_sample_percent', 'mirror_timeout_ms', 'mirror_max_body_bytes',
  ],
  timeouts: [
    'connect_timeout_s', 'read_timeout_s', 'send_timeout_s',
    'strip_path_prefix', 'add_path_prefix', 'path_rewrite_pattern', 'path_rewrite_replacement', 'retry_attempts', 'retry_on_methods',
  ],
  security: [
    // WAF moved in from General (v1.4.0 pass 1).
    'waf_enabled', 'waf_mode',
    'security_headers', 'max_body_mb', 'rate_limit_rps',
    'rate_limit_burst', 'ip_allowlist', 'ip_denylist',
    'basic_auth_username', 'basic_auth_password',
    'forward_auth_address', 'forward_auth_timeout_ms', 'forward_auth_response_headers',
    'mtls_ca_cert_pem', 'mtls_required', 'mtls_allowed_organizations',
  ],
  headers: [
    'proxy_headers', 'proxy_headers_remove',
    'response_headers', 'response_headers_remove',
  ],
  cors: [
    'cors_allowed_origins', 'cors_allowed_methods', 'cors_max_age_s',
  ],
  caching: [
    'cache_enabled', 'cache_ttl_s', 'cache_max_mb', 'stale_while_revalidate_s', 'stale_if_error_s',
    'cache_vary_headers',
  ],
  protection: [
    'max_connections', 'slowloris_threshold_ms',
    'auto_ban_threshold', 'auto_ban_duration_s',
    'rate_limit_capacity', 'rate_limit_refill_per_sec', 'rate_limit_scope',
    'geoip_mode', 'geoip_countries',
    'bot_enabled', 'bot_mode', 'bot_cookie_ttl_s', 'bot_pow_difficulty',
    'bot_captcha_alphabet',
    'bot_bypass_ip_cidrs', 'bot_bypass_asns', 'bot_bypass_countries',
    'bot_bypass_user_agents', 'bot_bypass_rdns', 'bot_only_country',
  ],
  // path_rules, header_rules, traffic_splits, mirror all absorbed into routing.
  response_rewrite: [
    'response_rewrite_rules', 'response_rewrite_max_body_bytes', 'response_rewrite_content_type_prefixes',
    // Compression temporarily hosted here until Transform tab absorbs it in the next pass.
    'compression_enabled',
  ],
};

function recordToText(rec: Record<string, string>): string {
  return Object.entries(rec).map(([k, v]) => `${k}=${v}`).join('\n');
}

function textToRecord(text: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const idx = trimmed.indexOf('=');
    if (idx > 0) {
      result[trimmed.slice(0, idx).trim()] = trimmed.slice(idx + 1).trim();
    }
  }
  return result;
}

/**
 * Parse a token list that accepts BOTH comma AND newline separators.
 *
 * Lorica's form inputs are inconsistent in which separator they
 * advertise (CSV for header names, one-per-line for IPs / CIDRs).
 * Accepting both here means a user who pastes from docs / a spread-
 * sheet / a previous route's export doesn't get surprised. Tokens
 * are trimmed and empty ones are dropped; this matches the behaviour
 * operators expect from similar fields in kubectl / nginx.conf.
 *
 * Kept alongside the legacy `csvToArray` / `linesToArray` because
 * some callers rely on the strict single-separator semantics (e.g.
 * preserving user-typed empty entries for validation surfacing).
 */
function tokenListToArray(text: string): string[] {
  return text
    .split(/[,\n]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function csvToArray(text: string): string[] {
  return text.split(',').map((s) => s.trim()).filter((s) => s.length > 0);
}

function linesToArray(text: string): string[] {
  return text.split('\n').map((s) => s.trim()).filter((s) => s.length > 0);
}

export function routeToFormState(route: RouteResponse): RouteFormState {
  return {
    hostname: route.hostname,
    path_prefix: route.path_prefix,
    backend_ids: [...route.backends],
    certificate_id: route.certificate_id ?? '',
    load_balancing: route.load_balancing,
    waf_enabled: route.waf_enabled,
    waf_mode: route.waf_mode ?? 'detection',
    enabled: route.enabled,
    force_https: route.force_https,
    redirect_hostname: route.redirect_hostname ?? '',
    redirect_to: route.redirect_to ?? '',
    hostname_aliases: route.hostname_aliases.join(', '),
    websocket_enabled: route.websocket_enabled,
    access_log_enabled: route.access_log_enabled,
    compression_enabled: route.compression_enabled,
    connect_timeout_s: route.connect_timeout_s,
    read_timeout_s: route.read_timeout_s,
    send_timeout_s: route.send_timeout_s,
    strip_path_prefix: route.strip_path_prefix ?? '',
    add_path_prefix: route.add_path_prefix ?? '',
    path_rewrite_pattern: route.path_rewrite_pattern ?? '',
    path_rewrite_replacement: route.path_rewrite_replacement ?? '',
    retry_attempts: route.retry_attempts != null ? String(route.retry_attempts) : '',
    security_headers: route.security_headers,
    max_body_mb: route.max_request_body_bytes != null ? String(route.max_request_body_bytes / (1024 * 1024)) : '',
    rate_limit_rps: route.rate_limit_rps != null ? String(route.rate_limit_rps) : '',
    rate_limit_burst: route.rate_limit_burst != null ? String(route.rate_limit_burst) : '',
    ip_allowlist: route.ip_allowlist.join('\n'),
    ip_denylist: route.ip_denylist.join('\n'),
    proxy_headers: recordToText(route.proxy_headers),
    proxy_headers_remove: route.proxy_headers_remove.join(', '),
    response_headers: recordToText(route.response_headers),
    response_headers_remove: route.response_headers_remove.join(', '),
    cors_allowed_origins: route.cors_allowed_origins.join(', '),
    cors_allowed_methods: route.cors_allowed_methods.join(', '),
    cors_max_age_s: route.cors_max_age_s != null ? String(route.cors_max_age_s) : '',
    cache_enabled: route.cache_enabled,
    cache_ttl_s: route.cache_ttl_s,
    cache_max_mb: Math.round(route.cache_max_bytes / 1048576),
    max_connections: route.max_connections != null ? String(route.max_connections) : '',
    slowloris_threshold_ms: route.slowloris_threshold_ms,
    auto_ban_threshold: route.auto_ban_threshold != null ? String(route.auto_ban_threshold) : '',
    auto_ban_duration_s: route.auto_ban_duration_s,
    path_rules: (route.path_rules ?? []).map((r) => ({
      path: r.path,
      match_type: r.match_type ?? 'prefix',
      backend_ids: r.backend_ids ?? [],
      cache_enabled: r.cache_enabled ?? null,
      cache_ttl_s: r.cache_ttl_s ?? null,
      response_headers: r.response_headers ? recordToText(r.response_headers) : '',
      response_headers_remove: r.response_headers_remove ? r.response_headers_remove.join(', ') : '',
      rate_limit_rps: r.rate_limit_rps != null ? String(r.rate_limit_rps) : '',
      rate_limit_burst: r.rate_limit_burst != null ? String(r.rate_limit_burst) : '',
      redirect_to: r.redirect_to ?? '',
      return_status: r.return_status != null ? String(r.return_status) : '',
    })),
    return_status: route.return_status != null ? String(route.return_status) : '',
    sticky_session: route.sticky_session ?? false,
    basic_auth_username: route.basic_auth_username ?? '',
    basic_auth_password: '',
    stale_while_revalidate_s: route.stale_while_revalidate_s ?? 10,
    stale_if_error_s: route.stale_if_error_s ?? 60,
    retry_on_methods: (route.retry_on_methods ?? []).join(', '),
    error_page_html: route.error_page_html ?? '',
    cache_vary_headers: (route.cache_vary_headers ?? []).join(', '),
    header_rules: (route.header_rules ?? []).map((r) => ({
      header_name: r.header_name,
      match_type: r.match_type ?? 'exact',
      value: r.value,
      backend_ids: [...(r.backend_ids ?? [])],
      disabled: r.disabled ?? false,
    })),
    traffic_splits: (route.traffic_splits ?? []).map((s) => ({
      name: s.name ?? '',
      weight_percent: s.weight_percent,
      backend_ids: [...(s.backend_ids ?? [])],
    })),
    forward_auth_address: route.forward_auth?.address ?? '',
    forward_auth_timeout_ms: route.forward_auth?.timeout_ms ?? 5000,
    forward_auth_response_headers: (route.forward_auth?.response_headers ?? []).join(', '),
    mirror_backend_ids: [...(route.mirror?.backend_ids ?? [])],
    mirror_sample_percent: route.mirror?.sample_percent ?? 100,
    mirror_timeout_ms: route.mirror?.timeout_ms ?? 5000,
    mirror_max_body_bytes: route.mirror?.max_body_bytes ?? 1048576,
    response_rewrite_rules: (route.response_rewrite?.rules ?? []).map((r) => ({
      pattern: r.pattern,
      replacement: r.replacement,
      is_regex: r.is_regex,
      max_replacements: r.max_replacements != null ? String(r.max_replacements) : '',
    })),
    response_rewrite_max_body_bytes: route.response_rewrite?.max_body_bytes ?? 1048576,
    response_rewrite_content_type_prefixes: (route.response_rewrite?.content_type_prefixes ?? []).join(', '),
    mtls_ca_cert_pem: route.mtls?.ca_cert_pem ?? '',
    mtls_required: route.mtls?.required ?? false,
    mtls_allowed_organizations: (route.mtls?.allowed_organizations ?? []).join(', '),
    rate_limit_capacity: route.rate_limit?.capacity ?? '',
    rate_limit_refill_per_sec: route.rate_limit?.refill_per_sec ?? '',
    rate_limit_scope: route.rate_limit?.scope ?? 'per_ip',
    geoip_mode: route.geoip?.mode ?? 'denylist',
    geoip_countries: (route.geoip?.countries ?? []).join(', '),
    bot_enabled: route.bot_protection != null,
    bot_mode: route.bot_protection?.mode ?? 'javascript',
    bot_cookie_ttl_s: route.bot_protection?.cookie_ttl_s ?? 86400,
    bot_pow_difficulty: route.bot_protection?.pow_difficulty ?? 18,
    bot_captcha_alphabet:
      route.bot_protection?.captcha_alphabet ??
      '23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ',
    bot_bypass_ip_cidrs: (route.bot_protection?.bypass?.ip_cidrs ?? []).join(', '),
    bot_bypass_asns: (route.bot_protection?.bypass?.asns ?? []).map(String).join(', '),
    bot_bypass_countries: (route.bot_protection?.bypass?.countries ?? []).join(', '),
    bot_bypass_user_agents: (route.bot_protection?.bypass?.user_agents ?? []).join('\n'),
    bot_bypass_rdns: (route.bot_protection?.bypass?.rdns ?? []).join('\n'),
    bot_only_country: (route.bot_protection?.only_country ?? []).join(', '),
  };
}

function headerRuleFormToRequest(rules: HeaderRuleFormState[]): HeaderRuleRequest[] | undefined {
  if (rules.length === 0) return undefined;
  return rules
    // Drop empty rules silently so an operator who clicks "+ Add" and then
    // navigates away doesn't send a malformed rule to the API.
    .filter((r) => r.header_name.trim().length > 0)
    .map((r) => ({
      header_name: r.header_name.trim(),
      match_type: r.match_type,
      value: r.value,
      backend_ids: [...r.backend_ids],
    }));
}

function responseRewriteFormToRequest(
  form: RouteFormState,
  isUpdate: boolean,
): ResponseRewriteConfigRequest | undefined {
  // An operator clicking "+ Add rule" then not filling anything in
  // produces an all-blank rule; drop those silently so they don't
  // trip API-layer validation.
  const rules = form.response_rewrite_rules
    .filter((r) => r.pattern.trim().length > 0)
    .map((r) => {
      const maxStr = r.max_replacements.trim();
      const max = maxStr === '' ? null : Number(maxStr);
      return {
        pattern: r.pattern,
        replacement: r.replacement,
        is_regex: r.is_regex,
        max_replacements: max,
      };
    });
  if (rules.length === 0) {
    // On update, empty rules = "disable the feature". On create,
    // omit so the row is inserted with NULL.
    return isUpdate
      ? { rules: [], max_body_bytes: 0, content_type_prefixes: [] }
      : undefined;
  }
  return {
    rules,
    max_body_bytes: form.response_rewrite_max_body_bytes,
    content_type_prefixes: form.response_rewrite_content_type_prefixes
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0),
  };
}

function mirrorFormToRequest(
  form: RouteFormState,
  isUpdate: boolean,
): MirrorConfigRequest | undefined {
  if (form.mirror_backend_ids.length === 0) {
    // On update, empty backends is the dashboard's "disable" signal.
    // On create, omit entirely so the row is inserted with NULL.
    return isUpdate
      ? { backend_ids: [], sample_percent: 0, timeout_ms: 0, max_body_bytes: 0 }
      : undefined;
  }
  return {
    backend_ids: [...form.mirror_backend_ids],
    sample_percent: form.mirror_sample_percent,
    timeout_ms: form.mirror_timeout_ms,
    max_body_bytes: form.mirror_max_body_bytes,
  };
}

function forwardAuthFormToRequest(
  form: RouteFormState,
  isUpdate: boolean,
): ForwardAuthConfigRequest | undefined {
  const addr = form.forward_auth_address.trim();
  if (addr === '') {
    // On update, an empty address signals "clear the feature" - send
    // an explicit empty-address object so the API disables it. On create,
    // leave it undefined so the row is inserted with forward_auth = NULL.
    return isUpdate
      ? { address: '', timeout_ms: 0, response_headers: [] }
      : undefined;
  }
  return {
    address: addr,
    timeout_ms: form.forward_auth_timeout_ms,
    response_headers: tokenListToArray(form.forward_auth_response_headers),
  };
}

function trafficSplitFormToRequest(
  splits: TrafficSplitFormState[],
): TrafficSplitRequest[] | undefined {
  if (splits.length === 0) return undefined;
  // Drop splits with no backends AND zero weight (the "+ Add new" default
  // before the operator fills anything in). A non-zero weight with empty
  // backends is left intact so the API surfaces the validation error.
  return splits
    .filter((s) => !(s.backend_ids.length === 0 && s.weight_percent === 0))
    .map((s) => ({
      name: s.name.trim(),
      weight_percent: s.weight_percent,
      backend_ids: [...s.backend_ids],
    }));
}

function pathRuleFormToRequest(rules: PathRuleFormState[]): PathRuleRequest[] | undefined {
  if (rules.length === 0) return undefined;
  return rules.map((r) => {
    const req: PathRuleRequest = { path: r.path };
    if (r.match_type) req.match_type = r.match_type;
    if (r.backend_ids.length > 0) req.backend_ids = r.backend_ids;
    if (r.cache_enabled != null) req.cache_enabled = r.cache_enabled;
    if (r.cache_ttl_s != null) req.cache_ttl_s = r.cache_ttl_s;
    if (r.response_headers.trim()) req.response_headers = textToRecord(r.response_headers);
    if (csvToArray(r.response_headers_remove).length > 0) req.response_headers_remove = csvToArray(r.response_headers_remove);
    if (r.rate_limit_rps) req.rate_limit_rps = Number(r.rate_limit_rps);
    if (r.rate_limit_burst) req.rate_limit_burst = Number(r.rate_limit_burst);
    if (r.redirect_to) req.redirect_to = r.redirect_to;
    if (r.return_status) req.return_status = Number(r.return_status);
    return req;
  });
}

function buildAdvancedFields(form: RouteFormState, isUpdate = false) {
  // For updates, empty clearable fields must send explicit empty values
  // (not undefined) so the API clears them. For creates, undefined = use defaults.
  const empty = <T>(val: T): T | undefined => isUpdate ? val : undefined;

  return {
    force_https: form.force_https,
    redirect_hostname: form.redirect_hostname || (isUpdate ? '' : undefined),
    redirect_to: form.redirect_to || (isUpdate ? '' : undefined),
    hostname_aliases: tokenListToArray(form.hostname_aliases).length > 0 ? tokenListToArray(form.hostname_aliases) : empty([]),
    websocket_enabled: form.websocket_enabled,
    access_log_enabled: form.access_log_enabled,
    connect_timeout_s: form.connect_timeout_s,
    read_timeout_s: form.read_timeout_s,
    send_timeout_s: form.send_timeout_s,
    strip_path_prefix: form.strip_path_prefix || (isUpdate ? '' : undefined),
    add_path_prefix: form.add_path_prefix || (isUpdate ? '' : undefined),
    path_rewrite_pattern: form.path_rewrite_pattern || (isUpdate ? '' : undefined),
    path_rewrite_replacement: form.path_rewrite_replacement || (isUpdate ? '' : undefined),
    security_headers: form.security_headers,
    max_request_body_bytes: form.max_body_mb ? Math.round(Number(form.max_body_mb) * 1024 * 1024) : empty(0),
    rate_limit_rps: form.rate_limit_rps ? Number(form.rate_limit_rps) : empty(0),
    rate_limit_burst: form.rate_limit_burst ? Number(form.rate_limit_burst) : empty(0),
    ip_allowlist: linesToArray(form.ip_allowlist).length > 0 ? linesToArray(form.ip_allowlist) : empty([]),
    ip_denylist: linesToArray(form.ip_denylist).length > 0 ? linesToArray(form.ip_denylist) : empty([]),
    proxy_headers: form.proxy_headers.trim() ? textToRecord(form.proxy_headers) : empty({}),
    proxy_headers_remove: csvToArray(form.proxy_headers_remove).length > 0 ? csvToArray(form.proxy_headers_remove) : empty([]),
    response_headers: form.response_headers.trim() ? textToRecord(form.response_headers) : empty({}),
    response_headers_remove: csvToArray(form.response_headers_remove).length > 0 ? csvToArray(form.response_headers_remove) : empty([]),
    cors_allowed_origins: csvToArray(form.cors_allowed_origins).length > 0 ? csvToArray(form.cors_allowed_origins) : empty([]),
    cors_allowed_methods: csvToArray(form.cors_allowed_methods).length > 0 ? csvToArray(form.cors_allowed_methods) : empty([]),
    cors_max_age_s: form.cors_max_age_s ? Number(form.cors_max_age_s) : empty(0),
    compression_enabled: form.compression_enabled,
    retry_attempts: form.retry_attempts ? Number(form.retry_attempts) : empty(0),
    cache_enabled: form.cache_enabled,
    cache_ttl_s: form.cache_ttl_s,
    cache_max_bytes: form.cache_max_mb * 1048576,
    max_connections: form.max_connections ? Number(form.max_connections) : empty(0),
    slowloris_threshold_ms: form.slowloris_threshold_ms,
    auto_ban_threshold: form.auto_ban_threshold ? Number(form.auto_ban_threshold) : empty(0),
    auto_ban_duration_s: form.auto_ban_duration_s,
    path_rules: pathRuleFormToRequest(form.path_rules) ?? (isUpdate ? [] : undefined),
    return_status: form.return_status ? Number(form.return_status) : empty(0),
    sticky_session: form.sticky_session,
    basic_auth_username: form.basic_auth_username || undefined,
    basic_auth_password: form.basic_auth_password || undefined,
    stale_while_revalidate_s: form.stale_while_revalidate_s,
    stale_if_error_s: form.stale_if_error_s,
    retry_on_methods: csvToArray(form.retry_on_methods).length > 0 ? csvToArray(form.retry_on_methods) : empty([]),
    // maintenance_mode is deliberately NOT sent from the drawer: it is
    // toggled from the Routes list (inline button) so the drawer is not
    // authoritative. Omitting the field keeps the backend's "missing =
    // no-op" contract, so a stale-form save cannot overwrite a freshly-
    // toggled value.
    // Clear-on-empty: empty text -> send "" on update (backend clears
    // the stored value), `undefined` on create (no field = use default).
    // Previously sent `undefined` on both, which meant an operator
    // wiping the textarea could not actually clear the stored HTML.
    error_page_html: form.error_page_html || (isUpdate ? '' : undefined),
    cache_vary_headers: tokenListToArray(form.cache_vary_headers).length > 0
      ? tokenListToArray(form.cache_vary_headers)
      : empty([]),
    header_rules: headerRuleFormToRequest(form.header_rules) ?? (isUpdate ? [] : undefined),
    traffic_splits: trafficSplitFormToRequest(form.traffic_splits) ?? (isUpdate ? [] : undefined),
    forward_auth: forwardAuthFormToRequest(form, isUpdate),
    mirror: mirrorFormToRequest(form, isUpdate),
    response_rewrite: responseRewriteFormToRequest(form, isUpdate),
    mtls: mtlsFormToRequest(form, isUpdate),
    rate_limit: rateLimitFormToRequest(form, isUpdate),
    geoip: geoipFormToRequest(form, isUpdate),
    bot_protection: botProtectionFormToRequest(form, isUpdate),
    // Explicit clear signal on update when the operator toggles
    // bot-protection off. The API contract is `missing = no-op`,
    // so we only emit the flag when both (a) this is an update
    // AND (b) the user has disabled the feature. A newly-created
    // route with bot_enabled=false simply omits the
    // bot_protection field (undefined above).
    bot_protection_disable: isUpdate && !form.bot_enabled ? true : undefined,
  };
}

function geoipFormToRequest(
  form: RouteFormState,
  isUpdate: boolean,
): { mode: 'allowlist' | 'denylist'; countries: string[] } | undefined {
  // Parse the CSV input: split on comma / whitespace, trim, drop
  // empty entries. API validation normalises to uppercase + dedups
  // + rejects non-ISO codes, so we do not try to duplicate that work
  // in the frontend.
  const countries = form.geoip_countries
    .split(/[,\s]+/)
    .map((c) => c.trim())
    .filter((c) => c.length > 0);

  // Empty countries + denylist mode on update is the explicit
  // "clear" signal (API maps this back to geoip=None). On create,
  // omit entirely so we do not store an empty row.
  if (countries.length === 0 && form.geoip_mode === 'denylist') {
    return isUpdate ? { mode: 'denylist', countries: [] } : undefined;
  }
  return { mode: form.geoip_mode, countries };
}

function botProtectionFormToRequest(
  form: RouteFormState,
  _isUpdate: boolean,
): {
  mode: 'cookie' | 'javascript' | 'captcha';
  cookie_ttl_s: number;
  pow_difficulty: number;
  captcha_alphabet: string;
  bypass: {
    ip_cidrs?: string[];
    asns?: number[];
    countries?: string[];
    user_agents?: string[];
    rdns?: string[];
  };
  only_country?: string[];
} | undefined {
  // Feature toggled off → omit the field entirely. Update
  // semantics on the backend say "missing = leave alone" so an
  // operator that toggles OFF via a PUT is currently a no-op;
  // proper "clear on update" support is a v1.4.x follow-up noted
  // in the docs.
  if (!form.bot_enabled) {
    return undefined;
  }

  const csv = (s: string) =>
    s.split(/[,\s]+/).map((c) => c.trim()).filter((c) => c.length > 0);
  const lines = (s: string) =>
    s.split(/\r?\n/).map((c) => c.trim()).filter((c) => c.length > 0);

  const bypass: {
    ip_cidrs?: string[];
    asns?: number[];
    countries?: string[];
    user_agents?: string[];
    rdns?: string[];
  } = {};
  const ip_cidrs = csv(form.bot_bypass_ip_cidrs);
  if (ip_cidrs.length > 0) bypass.ip_cidrs = ip_cidrs;
  // ASN entries parse to integers. We keep only well-formed
  // positive values so a stray `AS15169` or empty row does not
  // poison the list (the API validator also rejects zero).
  const asns = csv(form.bot_bypass_asns)
    .map((v) => Number(v.replace(/^AS/i, '')))
    .filter((n) => Number.isFinite(n) && n > 0);
  if (asns.length > 0) bypass.asns = asns;
  const countries = csv(form.bot_bypass_countries);
  if (countries.length > 0) bypass.countries = countries;
  const user_agents = lines(form.bot_bypass_user_agents);
  if (user_agents.length > 0) bypass.user_agents = user_agents;
  const rdns = lines(form.bot_bypass_rdns);
  if (rdns.length > 0) bypass.rdns = rdns;

  const only_country = csv(form.bot_only_country);
  const only_country_opt = only_country.length > 0 ? only_country : undefined;

  return {
    mode: form.bot_mode,
    cookie_ttl_s: form.bot_cookie_ttl_s,
    pow_difficulty: form.bot_pow_difficulty,
    captcha_alphabet: form.bot_captcha_alphabet,
    bypass,
    only_country: only_country_opt,
  };
}

function rateLimitFormToRequest(
  form: RouteFormState,
  isUpdate: boolean,
): { capacity: number; refill_per_sec: number; scope: 'per_ip' | 'per_route' } | undefined {
  const capacity =
    typeof form.rate_limit_capacity === 'number'
      ? form.rate_limit_capacity
      : 0;
  if (capacity === 0) {
    // On update, capacity=0 is the explicit "disable" signal (API
    // clears `rate_limit` to None). On create, omit entirely.
    return isUpdate
      ? { capacity: 0, refill_per_sec: 0, scope: form.rate_limit_scope }
      : undefined;
  }
  const refill =
    typeof form.rate_limit_refill_per_sec === 'number'
      ? form.rate_limit_refill_per_sec
      : 0;
  return {
    capacity,
    refill_per_sec: refill,
    scope: form.rate_limit_scope,
  };
}

function mtlsFormToRequest(
  form: RouteFormState,
  isUpdate: boolean,
): MtlsConfigRequest | undefined {
  const pem = form.mtls_ca_cert_pem.trim();
  if (pem === '') {
    // On update, empty PEM = clear the feature (API treats an
    // empty ca_cert_pem as "disable"). On create, omit entirely.
    return isUpdate
      ? { ca_cert_pem: '', required: false, allowed_organizations: [] }
      : undefined;
  }
  return {
    ca_cert_pem: pem,
    required: form.mtls_required,
    allowed_organizations: tokenListToArray(form.mtls_allowed_organizations),
  };
}

export function formStateToCreateRequest(form: RouteFormState): CreateRouteRequest {
  return {
    hostname: form.hostname,
    path_prefix: form.path_prefix || '/',
    backend_ids: form.backend_ids.length > 0 ? form.backend_ids : undefined,
    certificate_id: form.certificate_id || undefined,
    load_balancing: form.load_balancing,
    waf_enabled: form.waf_enabled,
    waf_mode: form.waf_mode,
    ...buildAdvancedFields(form),
  };
}

export function formStateToUpdateRequest(form: RouteFormState): UpdateRouteRequest {
  return {
    hostname: form.hostname,
    path_prefix: form.path_prefix,
    backend_ids: form.backend_ids,
    certificate_id: form.certificate_id !== undefined ? form.certificate_id : undefined,
    load_balancing: form.load_balancing,
    waf_enabled: form.waf_enabled,
    waf_mode: form.waf_mode,
    enabled: form.enabled,
    ...buildAdvancedFields(form, true),
  };
}

export function getModifiedFields(form: RouteFormState): Set<string> {
  const modified = new Set<string>();
  for (const key of Object.keys(ROUTE_DEFAULTS) as (keyof RouteFormState)[]) {
    if (key === 'path_rules') {
      if (form.path_rules.length > 0) modified.add(key);
      continue;
    }
    if (key === 'header_rules') {
      if (form.header_rules.length > 0) modified.add(key);
      continue;
    }
    if (key === 'traffic_splits') {
      if (form.traffic_splits.length > 0) modified.add(key);
      continue;
    }
    if (key === 'response_rewrite_rules') {
      if (form.response_rewrite_rules.length > 0) modified.add(key);
      continue;
    }
    const defaultVal = ROUTE_DEFAULTS[key];
    const currentVal = form[key];
    if (Array.isArray(defaultVal) && Array.isArray(currentVal)) {
      if (defaultVal.length !== currentVal.length || defaultVal.some((v, i) => v !== currentVal[i])) {
        modified.add(key);
      }
    } else if (defaultVal !== currentVal) {
      modified.add(key);
    }
  }
  return modified;
}

const HOSTNAME_PATTERN = /^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/;

function validateIpList(text: string): string {
  const lines = text.split('\n').map((s) => s.trim()).filter((s) => s.length > 0);
  for (const line of lines) {
    if (!line.includes('.') && !line.includes(':')) {
      return `Invalid IP or CIDR: "${line}"`;
    }
  }
  return '';
}

export function validateHostname(value: string): string {
  if (!value.trim()) return 'Hostname is required';
  if (value.trim() === '_') return ''; // catch-all hostname
  if (!HOSTNAME_PATTERN.test(value.trim())) return 'Invalid hostname';
  return '';
}

/**
 * Result shape for `validateRouteFormWithTab`. `tab` names the drawer
 * tab that owns the offending field so the caller can auto-switch
 * the view and put the user in front of the problem; `null` means
 * the error spans multiple tabs or couldn't be attributed (fall back
 * to just displaying the message).
 */
export interface ValidationResult {
  message: string;
  tab: string | null;
}

/**
 * Same checks as `validateRouteForm` but returns an object that
 * includes the owning tab id. RouteDrawer uses this to auto-switch
 * to the correct tab when a submit fails so users don't have to hunt
 * for the offending field (F-02 UX review finding).
 *
 * Kept alongside the legacy string-returning `validateRouteForm`
 * because 75 existing unit tests depend on the string contract.
 */
export function validateRouteFormWithTab(form: RouteFormState): ValidationResult {
  const r = (message: string, tab: string | null = null): ValidationResult => ({ message, tab });

  const hostErr = validateHostname(form.hostname);
  if (hostErr) return r(hostErr, 'general');
  if (form.path_prefix && !form.path_prefix.startsWith('/')) return r('Path prefix must start with /', 'general');
  if (form.connect_timeout_s < 1 || form.connect_timeout_s > 3600) return r('Connect timeout must be between 1 and 3600', 'timeouts');
  if (form.read_timeout_s < 1 || form.read_timeout_s > 3600) return r('Read timeout must be between 1 and 3600', 'timeouts');
  if (form.send_timeout_s < 1 || form.send_timeout_s > 3600) return r('Send timeout must be between 1 and 3600', 'timeouts');
  if (form.max_body_mb && Number(form.max_body_mb) <= 0) return r('Max body size must be greater than 0', 'security');
  if (form.rate_limit_rps && Number(form.rate_limit_rps) <= 0) return r('Rate limit RPS must be greater than 0', 'security');
  if (form.rate_limit_burst && Number(form.rate_limit_burst) <= 0) return r('Rate limit burst must be greater than 0', 'security');
  if (form.rate_limit_rps && form.rate_limit_burst && Number(form.rate_limit_burst) < Number(form.rate_limit_rps)) {
    return r('Rate limit burst must be >= RPS', 'security');
  }
  if (form.cors_max_age_s && Number(form.cors_max_age_s) <= 0) return r('CORS max age must be greater than 0', 'cors');
  const allowErr = validateIpList(form.ip_allowlist);
  if (allowErr) return r(`IP allowlist: ${allowErr}`, 'security');
  const denyErr = validateIpList(form.ip_denylist);
  if (denyErr) return r(`IP denylist: ${denyErr}`, 'security');
  // Traffic splits
  let totalWeight = 0;
  for (const s of form.traffic_splits) {
    if (!Number.isInteger(s.weight_percent) || s.weight_percent < 0 || s.weight_percent > 100) {
      return r(`Traffic split weight must be 0..100 (got ${s.weight_percent})`, 'routing');
    }
    if (s.weight_percent > 0 && s.backend_ids.length === 0) {
      return r('Traffic split with non-zero weight must select at least one backend', 'routing');
    }
    totalWeight += s.weight_percent;
  }
  if (totalWeight > 100) {
    return r(`Traffic splits: cumulative weight must be <= 100 (got ${totalWeight})`, 'routing');
  }
  // Forward auth
  if (form.forward_auth_address.trim() !== '') {
    const addr = form.forward_auth_address.trim();
    if (!/^https?:\/\/[^\s/]+/.test(addr)) {
      return r('Forward auth URL must start with http:// or https:// and include a host', 'security');
    }
    const t = Number(form.forward_auth_timeout_ms);
    if (!Number.isInteger(t) || t < 1 || t > 60000) {
      return r('Forward auth timeout must be 1..60000 ms', 'security');
    }
  }
  // Mirror (absorbed into Routing tab in the v1.4.0 UX refactor)
  if (form.mirror_backend_ids.length > 0) {
    const pct = Number(form.mirror_sample_percent);
    if (!Number.isInteger(pct) || pct < 0 || pct > 100) {
      return r('Mirror sample percent must be 0..100', 'routing');
    }
    const mt = Number(form.mirror_timeout_ms);
    if (!Number.isInteger(mt) || mt < 1 || mt > 60000) {
      return r('Mirror timeout must be 1..60000 ms', 'routing');
    }
    const mb = Number(form.mirror_max_body_bytes);
    if (!Number.isInteger(mb) || mb < 0 || mb > 128 * 1048576) {
      return r('Mirror max body bytes must be 0..134217728 (128 MiB; 0 = headers only)', 'routing');
    }
  }
  // Response rewrite
  if (form.response_rewrite_rules.length > 0) {
    const mb = Number(form.response_rewrite_max_body_bytes);
    if (!Number.isInteger(mb) || mb < 1 || mb > 128 * 1048576) {
      return r('Response rewrite max body bytes must be 1..134217728 (128 MiB)', 'response_rewrite');
    }
    for (let i = 0; i < form.response_rewrite_rules.length; i++) {
      const rule = form.response_rewrite_rules[i];
      if (!rule.pattern.trim()) {
        return r(`Response rewrite rule ${i + 1}: pattern must not be empty`, 'response_rewrite');
      }
      if (rule.is_regex) {
        try {
           
          new RegExp(rule.pattern);
        } catch (e) {
          return r(`Response rewrite rule ${i + 1}: invalid regex (${(e as Error).message})`, 'response_rewrite');
        }
      }
      const maxStr = rule.max_replacements.trim();
      if (maxStr !== '') {
        const n = Number(maxStr);
        if (!Number.isInteger(n) || n < 1) {
          return r(`Response rewrite rule ${i + 1}: max_replacements must be a positive integer (or empty for unlimited)`, 'response_rewrite');
        }
      }
    }
  }
  // mTLS
  const mtlsPem = form.mtls_ca_cert_pem.trim();
  if (mtlsPem !== '') {
    if (!/-----BEGIN CERTIFICATE-----/.test(mtlsPem)) {
      return r('mTLS CA PEM must contain at least one "-----BEGIN CERTIFICATE-----" block', 'security');
    }
    if (mtlsPem.length > 1048576) {
      return r('mTLS CA PEM must be 1 MiB or smaller; trim the bundle to issuing CAs only', 'security');
    }
    const raw = form.mtls_allowed_organizations;
    if (raw.trim() !== '') {
      const parts = raw.split(/[,\n]/);
      for (let i = 0; i < parts.length; i++) {
        if (parts[i].trim() === '') {
          return r(`mTLS allowed organization #${i + 1} must not be empty`, 'security');
        }
      }
    }
  }
  return r('', null);
}

export function validateRouteForm(form: RouteFormState): string {
  const hostErr = validateHostname(form.hostname);
  if (hostErr) return hostErr;
  if (form.path_prefix && !form.path_prefix.startsWith('/')) return 'Path prefix must start with /';
  if (form.connect_timeout_s < 1 || form.connect_timeout_s > 3600) return 'Connect timeout must be between 1 and 3600';
  if (form.read_timeout_s < 1 || form.read_timeout_s > 3600) return 'Read timeout must be between 1 and 3600';
  if (form.send_timeout_s < 1 || form.send_timeout_s > 3600) return 'Send timeout must be between 1 and 3600';
  if (form.max_body_mb && Number(form.max_body_mb) <= 0) return 'Max body size must be greater than 0';
  if (form.rate_limit_rps && Number(form.rate_limit_rps) <= 0) return 'Rate limit RPS must be greater than 0';
  if (form.rate_limit_burst && Number(form.rate_limit_burst) <= 0) return 'Rate limit burst must be greater than 0';
  if (form.rate_limit_rps && form.rate_limit_burst && Number(form.rate_limit_burst) < Number(form.rate_limit_rps)) {
    return 'Rate limit burst must be >= RPS';
  }
  if (form.cors_max_age_s && Number(form.cors_max_age_s) <= 0) return 'CORS max age must be greater than 0';
  const allowErr = validateIpList(form.ip_allowlist);
  if (allowErr) return `IP allowlist: ${allowErr}`;
  const denyErr = validateIpList(form.ip_denylist);
  if (denyErr) return `IP denylist: ${denyErr}`;
  // Traffic splits: weights in range + cumulative <= 100. Catching this
  // client-side gives an immediate red outline instead of a 400 round-trip.
  let totalWeight = 0;
  for (const s of form.traffic_splits) {
    if (!Number.isInteger(s.weight_percent) || s.weight_percent < 0 || s.weight_percent > 100) {
      return `Traffic split weight must be 0..100 (got ${s.weight_percent})`;
    }
    if (s.weight_percent > 0 && s.backend_ids.length === 0) {
      return 'Traffic split with non-zero weight must select at least one backend';
    }
    totalWeight += s.weight_percent;
  }
  if (totalWeight > 100) {
    return `Traffic splits: cumulative weight must be <= 100 (got ${totalWeight})`;
  }
  // Forward auth URL + timeout sanity. Empty address = feature off (OK).
  if (form.forward_auth_address.trim() !== '') {
    const addr = form.forward_auth_address.trim();
    if (!/^https?:\/\/[^\s/]+/.test(addr)) {
      return 'Forward auth URL must start with http:// or https:// and include a host';
    }
    const t = Number(form.forward_auth_timeout_ms);
    if (!Number.isInteger(t) || t < 1 || t > 60000) {
      return 'Forward auth timeout must be 1..60000 ms';
    }
  }
  // Mirror sanity. Empty backend list = feature off (OK).
  if (form.mirror_backend_ids.length > 0) {
    const pct = Number(form.mirror_sample_percent);
    if (!Number.isInteger(pct) || pct < 0 || pct > 100) {
      return 'Mirror sample percent must be 0..100';
    }
    const mt = Number(form.mirror_timeout_ms);
    if (!Number.isInteger(mt) || mt < 1 || mt > 60000) {
      return 'Mirror timeout must be 1..60000 ms';
    }
    const mb = Number(form.mirror_max_body_bytes);
    if (!Number.isInteger(mb) || mb < 0 || mb > 128 * 1048576) {
      return 'Mirror max body bytes must be 0..134217728 (128 MiB; 0 = headers only)';
    }
  }
  // Response rewrite sanity. Empty rules = feature off.
  if (form.response_rewrite_rules.length > 0) {
    const mb = Number(form.response_rewrite_max_body_bytes);
    if (!Number.isInteger(mb) || mb < 1 || mb > 128 * 1048576) {
      return 'Response rewrite max body bytes must be 1..134217728 (128 MiB)';
    }
    for (let i = 0; i < form.response_rewrite_rules.length; i++) {
      const r = form.response_rewrite_rules[i];
      if (!r.pattern.trim()) {
        return `Response rewrite rule ${i + 1}: pattern must not be empty`;
      }
      if (r.is_regex) {
        try {
           
          new RegExp(r.pattern);
        } catch (e) {
          return `Response rewrite rule ${i + 1}: invalid regex (${(e as Error).message})`;
        }
      }
      const maxStr = r.max_replacements.trim();
      if (maxStr !== '') {
        const n = Number(maxStr);
        if (!Number.isInteger(n) || n < 1) {
          return `Response rewrite rule ${i + 1}: max_replacements must be a positive integer (or empty for unlimited)`;
        }
      }
    }
  }
  // mTLS sanity. Empty ca_cert_pem = feature off.
  const mtlsPem = form.mtls_ca_cert_pem.trim();
  if (mtlsPem !== '') {
    if (!/-----BEGIN CERTIFICATE-----/.test(mtlsPem)) {
      return 'mTLS CA PEM must contain at least one "-----BEGIN CERTIFICATE-----" block';
    }
    if (mtlsPem.length > 1048576) {
      return 'mTLS CA PEM must be 1 MiB or smaller; trim the bundle to issuing CAs only';
    }
    // Match API behavior: any trimmed-empty entry is a hard reject,
    // including the single-element " " case and the leading/trailing
    // comma cases. An empty field (no commas, no text) is fine - it
    // means "no allowlist".
    const raw = form.mtls_allowed_organizations;
    if (raw.trim() !== '') {
      const parts = raw.split(',');
      for (let i = 0; i < parts.length; i++) {
        if (parts[i].trim() === '') {
          return `mTLS allowed organization #${i + 1} must not be empty`;
        }
      }
    }
  }
  return '';
}
