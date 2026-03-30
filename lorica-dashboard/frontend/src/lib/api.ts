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
}

export interface BackendResponse {
  id: string;
  address: string;
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

export interface WorkerStatus {
  worker_id: number;
  pid: number;
  last_heartbeat_ms: number;
  last_heartbeat_ago_s: number;
  healthy: boolean;
}
