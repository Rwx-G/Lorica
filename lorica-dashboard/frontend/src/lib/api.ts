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
};
