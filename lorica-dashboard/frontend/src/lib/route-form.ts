import type { RouteResponse, CreateRouteRequest, UpdateRouteRequest, PathRuleRequest } from './api';

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
  retry_on_methods: string;
  maintenance_mode: boolean;
  error_page_html: string;
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
  retry_on_methods: '',
  maintenance_mode: false,
  error_page_html: '',
};

// Tab field mappings for dot indicators
export const TAB_FIELDS: Record<string, (keyof RouteFormState)[]> = {
  general: [
    'hostname', 'path_prefix', 'force_https', 'redirect_hostname', 'redirect_to',
    'hostname_aliases', 'websocket_enabled', 'access_log_enabled',
    'compression_enabled', 'waf_enabled', 'return_status', 'sticky_session', 'maintenance_mode', 'error_page_html',
  ],
  timeouts: [
    'connect_timeout_s', 'read_timeout_s', 'send_timeout_s',
    'strip_path_prefix', 'add_path_prefix', 'path_rewrite_pattern', 'path_rewrite_replacement', 'retry_attempts', 'retry_on_methods',
  ],
  security: [
    'security_headers', 'max_body_mb', 'rate_limit_rps',
    'rate_limit_burst', 'ip_allowlist', 'ip_denylist',
    'basic_auth_username', 'basic_auth_password',
  ],
  headers: [
    'proxy_headers', 'proxy_headers_remove',
    'response_headers', 'response_headers_remove',
  ],
  cors: [
    'cors_allowed_origins', 'cors_allowed_methods', 'cors_max_age_s',
  ],
  caching: [
    'cache_enabled', 'cache_ttl_s', 'cache_max_mb',
  ],
  protection: [
    'max_connections', 'slowloris_threshold_ms',
    'auto_ban_threshold', 'auto_ban_duration_s',
  ],
  path_rules: ['path_rules'],
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
    retry_on_methods: (route.retry_on_methods ?? []).join(', '),
    maintenance_mode: route.maintenance_mode ?? false,
    error_page_html: route.error_page_html ?? '',
  };
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
    hostname_aliases: csvToArray(form.hostname_aliases).length > 0 ? csvToArray(form.hostname_aliases) : empty([]),
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
    retry_on_methods: csvToArray(form.retry_on_methods).length > 0 ? csvToArray(form.retry_on_methods) : empty([]),
    maintenance_mode: form.maintenance_mode,
    error_page_html: form.error_page_html || undefined,
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
  return '';
}
