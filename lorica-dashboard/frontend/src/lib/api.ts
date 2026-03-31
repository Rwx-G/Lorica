const BASE = '/api/v1';

export interface ApiError {
  code: string;
  message: string;
}

export interface ApiResponse<T> {
  data?: T;
  error?: ApiError;
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<ApiResponse<T>> {
  const opts: RequestInit = {
    method,
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
  };
  if (body !== undefined) {
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(`${BASE}${path}`, opts);
  const json = await res.json();
  if (!res.ok) {
    return { error: json.error ?? { code: 'unknown', message: res.statusText } };
  }
  return { data: json.data };
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  must_change_password: boolean;
  session_expires_at: string;
}

export interface StatusResponse {
  routes_count: number;
  backends_count: number;
  backends_healthy: number;
  backends_degraded: number;
  backends_down: number;
  certificates_count: number;
  certificates_expiring_soon: number;
}

export interface RouteResponse {
  id: string;
  hostname: string;
  path_prefix: string;
  backends: string[];
  certificate_id: string | null;
  load_balancing: string;
  waf_enabled: boolean;
  waf_mode: string;
  topology_type: string;
  enabled: boolean;
  force_https: boolean;
  redirect_hostname: string | null;
  hostname_aliases: string[];
  proxy_headers: Record<string, string>;
  response_headers: Record<string, string>;
  security_headers: string;
  connect_timeout_s: number;
  read_timeout_s: number;
  send_timeout_s: number;
  strip_path_prefix: string | null;
  add_path_prefix: string | null;
  access_log_enabled: boolean;
  proxy_headers_remove: string[];
  response_headers_remove: string[];
  max_request_body_bytes: number | null;
  websocket_enabled: boolean;
  rate_limit_rps: number | null;
  rate_limit_burst: number | null;
  ip_allowlist: string[];
  ip_denylist: string[];
  cors_allowed_origins: string[];
  cors_allowed_methods: string[];
  cors_max_age_s: number | null;
  compression_enabled: boolean;
  retry_attempts: number | null;
  created_at: string;
  updated_at: string;
}

export interface CreateRouteRequest {
  hostname: string;
  path_prefix?: string;
  backend_ids?: string[];
  certificate_id?: string;
  load_balancing?: string;
  topology_type?: string;
  waf_enabled?: boolean;
  waf_mode?: string;
  force_https?: boolean;
  redirect_hostname?: string;
  hostname_aliases?: string[];
  proxy_headers?: Record<string, string>;
  response_headers?: Record<string, string>;
  security_headers?: string;
  connect_timeout_s?: number;
  read_timeout_s?: number;
  send_timeout_s?: number;
  strip_path_prefix?: string;
  add_path_prefix?: string;
  access_log_enabled?: boolean;
  proxy_headers_remove?: string[];
  response_headers_remove?: string[];
  max_request_body_bytes?: number;
  websocket_enabled?: boolean;
  rate_limit_rps?: number;
  rate_limit_burst?: number;
  ip_allowlist?: string[];
  ip_denylist?: string[];
  cors_allowed_origins?: string[];
  cors_allowed_methods?: string[];
  cors_max_age_s?: number;
  compression_enabled?: boolean;
  retry_attempts?: number;
}

export interface UpdateRouteRequest {
  hostname?: string;
  path_prefix?: string;
  backend_ids?: string[];
  certificate_id?: string;
  load_balancing?: string;
  topology_type?: string;
  waf_enabled?: boolean;
  waf_mode?: string;
  enabled?: boolean;
  force_https?: boolean;
  redirect_hostname?: string;
  hostname_aliases?: string[];
  proxy_headers?: Record<string, string>;
  response_headers?: Record<string, string>;
  security_headers?: string;
  connect_timeout_s?: number;
  read_timeout_s?: number;
  send_timeout_s?: number;
  strip_path_prefix?: string;
  add_path_prefix?: string;
  access_log_enabled?: boolean;
  proxy_headers_remove?: string[];
  response_headers_remove?: string[];
  max_request_body_bytes?: number;
  websocket_enabled?: boolean;
  rate_limit_rps?: number;
  rate_limit_burst?: number;
  ip_allowlist?: string[];
  ip_denylist?: string[];
  cors_allowed_origins?: string[];
  cors_allowed_methods?: string[];
  cors_max_age_s?: number;
  compression_enabled?: boolean;
  retry_attempts?: number;
}

export interface BackendResponse {
  id: string;
  address: string;
  name: string;
  group_name: string;
  weight: number;
  health_status: string;
  health_check_enabled: boolean;
  health_check_interval_s: number;
  health_check_path: string | null;
  tls_upstream: boolean;
  created_at: string;
  updated_at: string;
}

export interface CertificateResponse {
  id: string;
  domain: string;
  san_domains: string[];
  fingerprint: string;
  issuer: string;
  not_before: string;
  not_after: string;
  is_acme: boolean;
  acme_auto_renew: boolean;
  created_at: string;
}

export interface CertificateDetailResponse extends CertificateResponse {
  cert_pem: string;
  associated_routes: string[];
}

export interface CreateCertificateRequest {
  domain: string;
  cert_pem: string;
  key_pem: string;
}

export interface UpdateCertificateRequest {
  domain?: string;
  cert_pem?: string;
  key_pem?: string;
}

export interface GenerateSelfSignedRequest {
  domain: string;
}

export interface LogEntry {
  id: number;
  timestamp: string;
  method: string;
  path: string;
  host: string;
  status: number;
  latency_ms: number;
  backend: string;
  error: string | null;
}

export interface LogsResponse {
  entries: LogEntry[];
  total: number;
}

export interface LogsQuery {
  route?: string;
  status?: number;
  status_min?: number;
  status_max?: number;
  time_from?: string;
  time_to?: string;
  search?: string;
  limit?: number;
  after_id?: number;
}

export interface HostMetrics {
  cpu_usage_percent: number;
  cpu_count: number;
  memory_total_bytes: number;
  memory_used_bytes: number;
  memory_usage_percent: number;
  disk_total_bytes: number;
  disk_used_bytes: number;
  disk_usage_percent: number;
}

export interface ProcessMetrics {
  memory_bytes: number;
  cpu_usage_percent: number;
}

export interface ProxyInfo {
  version: string;
  uptime_seconds: number;
  active_connections: number;
}

export interface SystemResponse {
  host: HostMetrics;
  process: ProcessMetrics;
  proxy: ProxyInfo;
}

export interface GlobalSettingsResponse {
  management_port: number;
  log_level: string;
  default_health_check_interval_s: number;
  cert_warning_days: number;
  cert_critical_days: number;
  default_topology_type: string;
}

export interface UpdateSettingsRequest {
  management_port?: number;
  log_level?: string;
  default_health_check_interval_s?: number;
  cert_warning_days?: number;
  cert_critical_days?: number;
  default_topology_type?: string;
}

export interface NotificationConfigResponse {
  id: string;
  channel: string;
  enabled: boolean;
  config: string;
  alert_types: string[];
}

export interface CreateNotificationRequest {
  channel: string;
  enabled?: boolean;
  config: string;
  alert_types: string[];
}

export interface UserPreferenceResponse {
  id: string;
  preference_key: string;
  value: string;
  created_at: string;
  updated_at: string;
}

export interface EntityDiff {
  added: string[];
  modified: string[];
  removed: string[];
}

export interface SettingChange {
  key: string;
  old_value: string;
  new_value: string;
}

export interface ImportDiffResponse {
  routes: EntityDiff;
  backends: EntityDiff;
  certificates: EntityDiff;
  route_backends: EntityDiff;
  notification_configs: EntityDiff;
  user_preferences: EntityDiff;
  admin_users: EntityDiff;
  global_settings: { changes: SettingChange[] };
}

export const api = {
  login: (creds: LoginRequest) =>
    request<LoginResponse>('POST', '/auth/login', creds),

  logout: () => request<void>('POST', '/auth/logout'),

  changePassword: (current_password: string, new_password: string) =>
    request<{ message: string }>('PUT', '/auth/password', {
      current_password,
      new_password,
    }),

  getStatus: () => request<StatusResponse>('GET', '/status'),

  listRoutes: () =>
    request<{ routes: RouteResponse[] }>('GET', '/routes'),

  createRoute: (body: CreateRouteRequest) =>
    request<RouteResponse>('POST', '/routes', body),

  getRoute: (id: string) =>
    request<RouteResponse>('GET', `/routes/${id}`),

  updateRoute: (id: string, body: UpdateRouteRequest) =>
    request<RouteResponse>('PUT', `/routes/${id}`, body),

  deleteRoute: (id: string) =>
    request<{ message: string }>('DELETE', `/routes/${id}`),

  listBackends: () =>
    request<{ backends: BackendResponse[] }>('GET', '/backends'),

  listCertificates: () =>
    request<{ certificates: CertificateResponse[] }>('GET', '/certificates'),

  getCertificate: (id: string) =>
    request<CertificateDetailResponse>('GET', `/certificates/${id}`),

  createCertificate: (body: CreateCertificateRequest) =>
    request<CertificateResponse>('POST', '/certificates', body),

  updateCertificate: (id: string, body: UpdateCertificateRequest) =>
    request<CertificateResponse>('PUT', `/certificates/${id}`, body),

  deleteCertificate: (id: string) =>
    request<{ message: string }>('DELETE', `/certificates/${id}`),

  generateSelfSigned: (body: GenerateSelfSignedRequest) =>
    request<CertificateResponse>('POST', '/certificates/self-signed', body),

  getLogs: (params?: LogsQuery) => {
    const query = new URLSearchParams();
    if (params?.route) query.set('route', params.route);
    if (params?.status !== undefined) query.set('status', String(params.status));
    if (params?.status_min !== undefined) query.set('status_min', String(params.status_min));
    if (params?.status_max !== undefined) query.set('status_max', String(params.status_max));
    if (params?.time_from) query.set('time_from', params.time_from);
    if (params?.time_to) query.set('time_to', params.time_to);
    if (params?.search) query.set('search', params.search);
    if (params?.limit !== undefined) query.set('limit', String(params.limit));
    if (params?.after_id !== undefined) query.set('after_id', String(params.after_id));
    const qs = query.toString();
    return request<LogsResponse>('GET', `/logs${qs ? `?${qs}` : ''}`);
  },

  clearLogs: () =>
    request<{ message: string }>('DELETE', '/logs'),

  getSystem: () =>
    request<SystemResponse>('GET', '/system'),

  // Settings
  getSettings: () =>
    request<GlobalSettingsResponse>('GET', '/settings'),

  updateSettings: (body: UpdateSettingsRequest) =>
    request<GlobalSettingsResponse>('PUT', '/settings', body),

  // Notifications
  listNotifications: () =>
    request<{ notifications: NotificationConfigResponse[] }>('GET', '/notifications'),

  createNotification: (body: CreateNotificationRequest) =>
    request<NotificationConfigResponse>('POST', '/notifications', body),

  updateNotification: (id: string, body: CreateNotificationRequest) =>
    request<NotificationConfigResponse>('PUT', `/notifications/${id}`, body),

  deleteNotification: (id: string) =>
    request<{ message: string }>('DELETE', `/notifications/${id}`),

  testNotification: (id: string) =>
    request<{ message: string; channel: string }>('POST', `/notifications/${id}/test`),

  // Preferences
  listPreferences: () =>
    request<{ preferences: UserPreferenceResponse[] }>('GET', '/preferences'),

  updatePreference: (id: string, value: string) =>
    request<UserPreferenceResponse>('PUT', `/preferences/${id}`, { value }),

  deletePreference: (id: string) =>
    request<{ message: string }>('DELETE', `/preferences/${id}`),

  // Config export/import
  exportConfig: async (): Promise<ApiResponse<string>> => {
    const res = await fetch(`${BASE}/config/export`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) {
      const json = await res.json();
      return { error: json.error ?? { code: 'unknown', message: res.statusText } };
    }
    const text = await res.text();
    return { data: text };
  },

  importPreview: (toml_content: string) =>
    request<ImportDiffResponse>('POST', '/config/import/preview', { toml_content }),

  importConfig: (toml_content: string) =>
    request<{ message: string }>('POST', '/config/import', { toml_content }),

  getWorkers: () =>
    request<{ workers: WorkerStatus[]; total: number }>('GET', '/workers'),

  // WAF
  getWafEvents: (params?: { limit?: number; category?: string }) => {
    const query = new URLSearchParams();
    if (params?.limit !== undefined) query.set('limit', String(params.limit));
    if (params?.category) query.set('category', params.category);
    const qs = query.toString();
    return request<WafEventsResponse>('GET', `/waf/events${qs ? `?${qs}` : ''}`);
  },

  getWafStats: () =>
    request<WafStatsResponse>('GET', '/waf/stats'),

  clearWafEvents: () =>
    request<{ cleared: boolean }>('DELETE', '/waf/events'),

  getWafRules: () =>
    request<WafRulesResponse>('GET', '/waf/rules'),

  toggleWafRule: (ruleId: number, enabled: boolean) =>
    request<{ rule_id: number; enabled: boolean }>('PUT', `/waf/rules/${ruleId}`, { enabled }),

  // IP Blocklist
  getBlocklistStatus: () =>
    request<BlocklistStatus>('GET', '/waf/blocklist'),

  toggleBlocklist: (enabled: boolean) =>
    request<{ enabled: boolean; ip_count: number }>('PUT', '/waf/blocklist', { enabled }),

  reloadBlocklist: () =>
    request<{ reloaded: boolean; ip_count: number; source: string }>('POST', '/waf/blocklist/reload'),

  // WAF Custom Rules
  listCustomRules: () =>
    request<{ rules: CustomWafRule[]; total: number }>('GET', '/waf/rules/custom'),

  createCustomRule: (body: CreateCustomRuleRequest) =>
    request<{ id: number; description: string; created: boolean }>('POST', '/waf/rules/custom', body),

  deleteCustomRule: (id: number) =>
    request<{ deleted: boolean; id: number }>('DELETE', `/waf/rules/custom/${id}`),

  // ACME Certificate Provisioning
  provisionAcme: (body: AcmeProvisionRequest) =>
    request<AcmeProvisionResponse>('POST', '/acme/provision', body),

  provisionAcmeDns: (body: AcmeDnsProvisionRequest) =>
    request<AcmeProvisionResponse>('POST', '/acme/provision-dns', body),

  // Backends CRUD
  getBackend: (id: string) =>
    request<BackendResponse>('GET', `/backends/${id}`),

  createBackend: (body: CreateBackendRequest) =>
    request<BackendResponse>('POST', '/backends', body),

  updateBackend: (id: string, body: UpdateBackendRequest) =>
    request<BackendResponse>('PUT', `/backends/${id}`, body),

  deleteBackend: (id: string) =>
    request<{ message: string }>('DELETE', `/backends/${id}`),

  // SLA
  getSlaOverview: () =>
    request<SlaSummary[]>('GET', '/sla/overview'),

  getRouteSla: (routeId: string) =>
    request<SlaSummary[]>('GET', `/sla/routes/${routeId}`),

  getRouteSlaActive: (routeId: string) =>
    request<SlaSummary[]>('GET', `/sla/routes/${routeId}/active`),

  getRouteSlaBuckets: (routeId: string, params?: { from?: string; to?: string; source?: string }) => {
    const query = new URLSearchParams();
    if (params?.from) query.set('from', params.from);
    if (params?.to) query.set('to', params.to);
    if (params?.source) query.set('source', params.source);
    const qs = query.toString();
    return request<SlaBucket[]>('GET', `/sla/routes/${routeId}/buckets${qs ? `?${qs}` : ''}`);
  },

  getSlaConfig: (routeId: string) =>
    request<SlaConfigResponse>('GET', `/sla/routes/${routeId}/config`),

  updateSlaConfig: (routeId: string, body: UpdateSlaConfigRequest) =>
    request<SlaConfigResponse>('PUT', `/sla/routes/${routeId}/config`, body),

  exportSla: (routeId: string, format: 'json' | 'csv' = 'json') => {
    const url = `${BASE}/sla/routes/${routeId}/export?format=${format}`;
    return fetch(url, { credentials: 'same-origin' });
  },

  // Probes
  listProbes: () =>
    request<ProbeConfigResponse[]>('GET', '/probes'),

  listProbesForRoute: (routeId: string) =>
    request<ProbeConfigResponse[]>('GET', `/probes/route/${routeId}`),

  createProbe: (body: CreateProbeRequest) =>
    request<ProbeConfigResponse>('POST', '/probes', body),

  updateProbe: (id: string, body: UpdateProbeRequest) =>
    request<ProbeConfigResponse>('PUT', `/probes/${id}`, body),

  deleteProbe: (id: string) =>
    request<{ deleted: string }>('DELETE', `/probes/${id}`),

  // Load Testing
  listLoadTestConfigs: () =>
    request<LoadTestConfigResponse[]>('GET', '/loadtest/configs'),

  createLoadTestConfig: (body: CreateLoadTestRequest) =>
    request<LoadTestConfigResponse>('POST', '/loadtest/configs', body),

  deleteLoadTestConfig: (id: string) =>
    request<{ deleted: string }>('DELETE', `/loadtest/configs/${id}`),

  cloneLoadTestConfig: (id: string, name?: string) =>
    request<LoadTestConfigResponse>('POST', `/loadtest/configs/${id}/clone`, { name }),

  startLoadTest: (configId: string) =>
    request<{ status: string; warnings?: string[] }>('POST', `/loadtest/start/${configId}`),

  startLoadTestConfirmed: (configId: string) =>
    request<{ status: string }>('POST', `/loadtest/start/${configId}/confirm`),

  getLoadTestStatus: () =>
    request<LoadTestProgress>('GET', '/loadtest/status'),

  abortLoadTest: () =>
    request<{ status: string }>('POST', '/loadtest/abort'),

  getLoadTestResults: (configId: string) =>
    request<LoadTestResultResponse[]>('GET', `/loadtest/results/${configId}`),

  compareLoadTestResults: (configId: string) =>
    request<LoadTestComparison>('GET', `/loadtest/results/${configId}/compare`),
};

export interface WafEvent {
  rule_id: number;
  description: string;
  category: string;
  severity: number;
  matched_field: string;
  matched_value: string;
  timestamp: string;
}

export interface WafEventsResponse {
  events: WafEvent[];
  total: number;
  rule_count: number;
}

export interface WafCategoryCount {
  category: string;
  count: number;
}

export interface WafStatsResponse {
  total_events: number;
  rule_count: number;
  by_category: WafCategoryCount[];
}

export interface WafRuleSummary {
  id: number;
  description: string;
  category: string;
  severity: number;
  enabled: boolean;
}

export interface WafRulesResponse {
  rules: WafRuleSummary[];
  total: number;
  enabled: number;
}

export interface CustomWafRule {
  id: number;
  description: string;
  category: string;
  severity: number;
  pattern: string;
}

export interface CreateCustomRuleRequest {
  id: number;
  description: string;
  category: string;
  pattern: string;
  severity?: number;
}

export interface AcmeProvisionRequest {
  domain: string;
  staging?: boolean;
  contact_email?: string;
}

export interface AcmeDnsProvisionRequest {
  domain: string;
  staging?: boolean;
  contact_email?: string;
  dns: {
    provider: string;
    zone_id: string;
    api_token: string;
    api_secret?: string;
  };
}

export interface AcmeProvisionResponse {
  status: string;
  domain: string;
  staging: boolean;
  message: string;
}

export interface BlocklistStatus {
  enabled: boolean;
  ip_count: number;
  source: string;
}

export interface WorkerStatus {
  worker_id: number;
  pid: number;
  last_heartbeat_ms: number;
  last_heartbeat_ago_s: number;
  healthy: boolean;
}

// --- SLA ---

export interface SlaSummary {
  route_id: string;
  window: string;
  total_requests: number;
  successful_requests: number;
  sla_pct: number;
  avg_latency_ms: number;
  p50_latency_ms: number;
  p95_latency_ms: number;
  p99_latency_ms: number;
  target_pct: number;
  meets_target: boolean;
}

export interface SlaBucket {
  id: number;
  route_id: string;
  bucket_start: string;
  request_count: number;
  success_count: number;
  error_count: number;
  latency_sum_ms: number;
  latency_min_ms: number;
  latency_max_ms: number;
  latency_p50_ms: number;
  latency_p95_ms: number;
  latency_p99_ms: number;
  source: string;
  cfg_max_latency_ms: number;
  cfg_status_min: number;
  cfg_status_max: number;
  cfg_target_pct: number;
}

export interface SlaConfigResponse {
  route_id: string;
  target_pct: number;
  max_latency_ms: number;
  success_status_min: number;
  success_status_max: number;
  created_at: string;
  updated_at: string;
}

export interface UpdateSlaConfigRequest {
  target_pct?: number;
  max_latency_ms?: number;
  success_status_min?: number;
  success_status_max?: number;
}

// --- Probes ---

export interface ProbeConfigResponse {
  id: string;
  route_id: string;
  method: string;
  path: string;
  expected_status: number;
  interval_s: number;
  timeout_ms: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateProbeRequest {
  route_id: string;
  method?: string;
  path?: string;
  expected_status?: number;
  interval_s?: number;
  timeout_ms?: number;
}

export interface UpdateProbeRequest {
  method?: string;
  path?: string;
  expected_status?: number;
  interval_s?: number;
  timeout_ms?: number;
  enabled?: boolean;
}

// --- Load Testing ---

export interface LoadTestConfigResponse {
  id: string;
  name: string;
  target_url: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
  concurrency: number;
  requests_per_second: number;
  duration_s: number;
  error_threshold_pct: number;
  schedule_cron: string | null;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateLoadTestRequest {
  name: string;
  target_url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  concurrency?: number;
  requests_per_second?: number;
  duration_s?: number;
  error_threshold_pct?: number;
  schedule_cron?: string;
}

export interface LoadTestResultResponse {
  id: string;
  config_id: string;
  started_at: string;
  finished_at: string;
  total_requests: number;
  successful_requests: number;
  failed_requests: number;
  avg_latency_ms: number;
  p50_latency_ms: number;
  p95_latency_ms: number;
  p99_latency_ms: number;
  min_latency_ms: number;
  max_latency_ms: number;
  throughput_rps: number;
  aborted: boolean;
  abort_reason: string | null;
}

export interface LoadTestProgress {
  total_requests: number;
  successful_requests: number;
  failed_requests: number;
  current_rps: number;
  avg_latency_ms: number;
  error_rate_pct: number;
  elapsed_s: number;
  active: boolean;
  aborted: boolean;
  abort_reason: string | null;
}

export interface LoadTestComparison {
  current: LoadTestResultResponse;
  previous: LoadTestResultResponse | null;
  latency_delta_pct: number | null;
  throughput_delta_pct: number | null;
}

// --- Backend Management ---

export interface CreateBackendRequest {
  address: string;
  name?: string;
  group_name?: string;
  weight?: number;
  health_check_enabled?: boolean;
  health_check_interval_s?: number;
  health_check_path?: string;
  tls_upstream?: boolean;
}

export interface UpdateBackendRequest {
  address?: string;
  name?: string;
  group_name?: string;
  weight?: number;
  health_check_enabled?: boolean;
  health_check_interval_s?: number;
  health_check_path?: string;
  tls_upstream?: boolean;
}
