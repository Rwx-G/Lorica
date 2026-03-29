import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from './api';

const mockRoute = {
  id: '123',
  hostname: 'example.com',
  path_prefix: '/',
  backends: ['b1'],
  certificate_id: null,
  load_balancing: 'round_robin',
  waf_enabled: false,
  topology_type: 'single_vm',
  enabled: true,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

beforeEach(() => {
  vi.restoreAllMocks();
});

function mockFetch(data: unknown, ok = true, status = 200) {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue({
      ok,
      status,
      statusText: ok ? 'OK' : 'Bad Request',
      json: () => Promise.resolve(ok ? { data } : { error: data }),
    }),
  );
}

describe('api.listRoutes', () => {
  it('calls GET /api/v1/routes and returns route list', async () => {
    mockFetch({ routes: [mockRoute] });
    const res = await api.listRoutes();
    expect(res.data?.routes).toHaveLength(1);
    expect(res.data?.routes[0].hostname).toBe('example.com');
    expect(fetch).toHaveBeenCalledWith('/api/v1/routes', expect.objectContaining({ method: 'GET' }));
  });
});

describe('api.createRoute', () => {
  it('calls POST /api/v1/routes with body', async () => {
    mockFetch(mockRoute);
    const res = await api.createRoute({ hostname: 'test.com' });
    expect(res.data?.id).toBe('123');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/routes',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ hostname: 'test.com' }),
      }),
    );
  });
});

describe('api.updateRoute', () => {
  it('calls PUT /api/v1/routes/:id with body', async () => {
    mockFetch(mockRoute);
    const res = await api.updateRoute('123', { hostname: 'new.com' });
    expect(res.data?.id).toBe('123');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/routes/123',
      expect.objectContaining({ method: 'PUT' }),
    );
  });
});

describe('api.deleteRoute', () => {
  it('calls DELETE /api/v1/routes/:id', async () => {
    mockFetch({ message: 'route deleted' });
    const res = await api.deleteRoute('123');
    expect(res.data?.message).toBe('route deleted');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/routes/123',
      expect.objectContaining({ method: 'DELETE' }),
    );
  });
});

describe('api error handling', () => {
  it('returns error object on non-ok response', async () => {
    mockFetch({ code: 'not_found', message: 'route not found' }, false, 404);
    const res = await api.getRoute('missing');
    expect(res.error?.code).toBe('not_found');
    expect(res.error?.message).toBe('route not found');
  });
});

describe('api.listBackends', () => {
  it('calls GET /api/v1/backends', async () => {
    mockFetch({ backends: [] });
    const res = await api.listBackends();
    expect(res.data?.backends).toHaveLength(0);
    expect(fetch).toHaveBeenCalledWith('/api/v1/backends', expect.objectContaining({ method: 'GET' }));
  });
});

describe('api.listCertificates', () => {
  it('calls GET /api/v1/certificates', async () => {
    mockFetch({ certificates: [] });
    const res = await api.listCertificates();
    expect(res.data?.certificates).toHaveLength(0);
    expect(fetch).toHaveBeenCalledWith('/api/v1/certificates', expect.objectContaining({ method: 'GET' }));
  });
});

const mockCert = {
  id: 'cert-1',
  domain: 'example.com',
  san_domains: [],
  fingerprint: 'AA:BB:CC',
  issuer: 'Test CA',
  not_before: '2026-01-01T00:00:00Z',
  not_after: '2027-01-01T00:00:00Z',
  is_acme: false,
  acme_auto_renew: false,
  created_at: '2026-01-01T00:00:00Z',
};

describe('api.getCertificate', () => {
  it('calls GET /api/v1/certificates/:id and returns detail', async () => {
    mockFetch({ ...mockCert, cert_pem: '---PEM---', associated_routes: ['r1'] });
    const res = await api.getCertificate('cert-1');
    expect(res.data?.domain).toBe('example.com');
    expect(res.data?.cert_pem).toBe('---PEM---');
    expect(res.data?.associated_routes).toEqual(['r1']);
    expect(fetch).toHaveBeenCalledWith('/api/v1/certificates/cert-1', expect.objectContaining({ method: 'GET' }));
  });
});

describe('api.createCertificate', () => {
  it('calls POST /api/v1/certificates with body', async () => {
    mockFetch(mockCert);
    const res = await api.createCertificate({ domain: 'test.com', cert_pem: 'cert', key_pem: 'key' });
    expect(res.data?.id).toBe('cert-1');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/certificates',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ domain: 'test.com', cert_pem: 'cert', key_pem: 'key' }),
      }),
    );
  });
});

describe('api.updateCertificate', () => {
  it('calls PUT /api/v1/certificates/:id with body', async () => {
    mockFetch(mockCert);
    const res = await api.updateCertificate('cert-1', { domain: 'new.com' });
    expect(res.data?.id).toBe('cert-1');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/certificates/cert-1',
      expect.objectContaining({ method: 'PUT' }),
    );
  });
});

describe('api.deleteCertificate', () => {
  it('calls DELETE /api/v1/certificates/:id', async () => {
    mockFetch({ message: 'certificate deleted' });
    const res = await api.deleteCertificate('cert-1');
    expect(res.data?.message).toBe('certificate deleted');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/certificates/cert-1',
      expect.objectContaining({ method: 'DELETE' }),
    );
  });
});

describe('api.deleteCertificate conflict', () => {
  it('returns error on 409 when routes reference the cert', async () => {
    mockFetch({ code: 'conflict', message: 'certificate is referenced by routes: r1' }, false, 409);
    const res = await api.deleteCertificate('cert-1');
    expect(res.error?.code).toBe('conflict');
  });
});

describe('api.generateSelfSigned', () => {
  it('calls POST /api/v1/certificates/self-signed with domain', async () => {
    mockFetch(mockCert);
    const res = await api.generateSelfSigned({ domain: 'localhost' });
    expect(res.data?.id).toBe('cert-1');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/certificates/self-signed',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ domain: 'localhost' }),
      }),
    );
  });
});

// ---- Logs API Tests ----

const mockLogEntry = {
  id: 1,
  timestamp: '2026-01-01T00:00:00Z',
  method: 'GET',
  path: '/api/test',
  host: 'example.com',
  status: 200,
  latency_ms: 15,
  backend: '10.0.0.1:8080',
  error: null,
};

describe('api.getLogs', () => {
  it('calls GET /api/v1/logs without params', async () => {
    mockFetch({ entries: [mockLogEntry], total: 1 });
    const res = await api.getLogs();
    expect(res.data?.entries).toHaveLength(1);
    expect(res.data?.total).toBe(1);
    expect(fetch).toHaveBeenCalledWith('/api/v1/logs', expect.objectContaining({ method: 'GET' }));
  });

  it('passes query params for filtering', async () => {
    mockFetch({ entries: [], total: 0 });
    await api.getLogs({ route: 'example.com', status_min: 400, search: 'error' });
    const url = (fetch as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    expect(url).toContain('route=example.com');
    expect(url).toContain('status_min=400');
    expect(url).toContain('search=error');
  });
});

describe('api.clearLogs', () => {
  it('calls DELETE /api/v1/logs', async () => {
    mockFetch({ message: 'logs cleared' });
    const res = await api.clearLogs();
    expect(res.data?.message).toBe('logs cleared');
    expect(fetch).toHaveBeenCalledWith('/api/v1/logs', expect.objectContaining({ method: 'DELETE' }));
  });
});

// ---- System API Tests ----

const mockSystem = {
  host: {
    cpu_usage_percent: 25.5,
    cpu_count: 8,
    memory_total_bytes: 16000000000,
    memory_used_bytes: 8000000000,
    memory_usage_percent: 50.0,
    disk_total_bytes: 500000000000,
    disk_used_bytes: 250000000000,
    disk_usage_percent: 50.0,
  },
  process: {
    memory_bytes: 50000000,
    cpu_usage_percent: 2.3,
  },
  proxy: {
    version: '0.3.0',
    uptime_seconds: 3600,
    active_connections: 42,
  },
};

describe('api.getSystem', () => {
  it('calls GET /api/v1/system and returns metrics', async () => {
    mockFetch(mockSystem);
    const res = await api.getSystem();
    expect(res.data?.host.cpu_count).toBe(8);
    expect(res.data?.proxy.version).toBe('0.3.0');
    expect(res.data?.process.memory_bytes).toBe(50000000);
    expect(fetch).toHaveBeenCalledWith('/api/v1/system', expect.objectContaining({ method: 'GET' }));
  });
});

// ---- Settings API Tests ----

const mockSettings = {
  management_port: 9443,
  log_level: 'info',
  default_health_check_interval_s: 10,
};

describe('api.getSettings', () => {
  it('calls GET /api/v1/settings', async () => {
    mockFetch(mockSettings);
    const res = await api.getSettings();
    expect(res.data?.management_port).toBe(9443);
    expect(res.data?.log_level).toBe('info');
    expect(fetch).toHaveBeenCalledWith('/api/v1/settings', expect.objectContaining({ method: 'GET' }));
  });
});

describe('api.updateSettings', () => {
  it('calls PUT /api/v1/settings with body', async () => {
    mockFetch({ ...mockSettings, log_level: 'debug' });
    const res = await api.updateSettings({ log_level: 'debug' });
    expect(res.data?.log_level).toBe('debug');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/settings',
      expect.objectContaining({ method: 'PUT' }),
    );
  });
});

// ---- Notifications API Tests ----

const mockNotification = {
  id: 'notif-1',
  channel: 'email',
  enabled: true,
  config: '{"smtp_host": "mail.example.com"}',
  alert_types: ['backend_down'],
};

describe('api.listNotifications', () => {
  it('calls GET /api/v1/notifications', async () => {
    mockFetch({ notifications: [mockNotification] });
    const res = await api.listNotifications();
    expect(res.data?.notifications).toHaveLength(1);
    expect(res.data?.notifications[0].channel).toBe('email');
    expect(fetch).toHaveBeenCalledWith('/api/v1/notifications', expect.objectContaining({ method: 'GET' }));
  });
});

describe('api.createNotification', () => {
  it('calls POST /api/v1/notifications with body', async () => {
    mockFetch(mockNotification);
    const res = await api.createNotification({
      channel: 'email',
      config: '{}',
      alert_types: ['backend_down'],
    });
    expect(res.data?.id).toBe('notif-1');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/notifications',
      expect.objectContaining({ method: 'POST' }),
    );
  });
});

describe('api.updateNotification', () => {
  it('calls PUT /api/v1/notifications/:id', async () => {
    mockFetch({ ...mockNotification, enabled: false });
    const res = await api.updateNotification('notif-1', {
      channel: 'email',
      enabled: false,
      config: '{}',
      alert_types: [],
    });
    expect(res.data?.enabled).toBe(false);
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/notifications/notif-1',
      expect.objectContaining({ method: 'PUT' }),
    );
  });
});

describe('api.deleteNotification', () => {
  it('calls DELETE /api/v1/notifications/:id', async () => {
    mockFetch({ message: 'notification config deleted' });
    const res = await api.deleteNotification('notif-1');
    expect(res.data?.message).toBe('notification config deleted');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/notifications/notif-1',
      expect.objectContaining({ method: 'DELETE' }),
    );
  });
});

// ---- Preferences API Tests ----

describe('api.listPreferences', () => {
  it('calls GET /api/v1/preferences', async () => {
    mockFetch({ preferences: [] });
    const res = await api.listPreferences();
    expect(res.data?.preferences).toHaveLength(0);
    expect(fetch).toHaveBeenCalledWith('/api/v1/preferences', expect.objectContaining({ method: 'GET' }));
  });
});

describe('api.updatePreference', () => {
  it('calls PUT /api/v1/preferences/:id with value', async () => {
    mockFetch({ id: 'p1', preference_key: 'self_signed', value: 'always', created_at: '', updated_at: '' });
    const res = await api.updatePreference('p1', 'always');
    expect(res.data?.value).toBe('always');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/preferences/p1',
      expect.objectContaining({
        method: 'PUT',
        body: JSON.stringify({ value: 'always' }),
      }),
    );
  });
});

describe('api.deletePreference', () => {
  it('calls DELETE /api/v1/preferences/:id', async () => {
    mockFetch({ message: 'preference deleted' });
    const res = await api.deletePreference('p1');
    expect(res.data?.message).toBe('preference deleted');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/preferences/p1',
      expect.objectContaining({ method: 'DELETE' }),
    );
  });
});

// ---- Config Export/Import API Tests ----

describe('api.exportConfig', () => {
  it('calls POST /api/v1/config/export and returns TOML text', async () => {
    const tomlContent = 'version = 1\n[global_settings]\nmanagement_port = 9443\n';
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        statusText: 'OK',
        text: () => Promise.resolve(tomlContent),
      }),
    );
    const res = await api.exportConfig();
    expect(res.data).toContain('version = 1');
    expect(fetch).toHaveBeenCalledWith('/api/v1/config/export', expect.objectContaining({ method: 'POST' }));
  });
});

describe('api.importPreview', () => {
  it('calls POST /api/v1/config/import/preview and returns diff', async () => {
    const diff = {
      routes: { added: ['new-route (r1)'], modified: [], removed: [] },
      backends: { added: [], modified: [], removed: [] },
      certificates: { added: [], modified: [], removed: [] },
      route_backends: { added: [], modified: [], removed: [] },
      notification_configs: { added: [], modified: [], removed: [] },
      user_preferences: { added: [], modified: [], removed: [] },
      admin_users: { added: [], modified: [], removed: [] },
      global_settings: { changes: [] },
    };
    mockFetch(diff);
    const res = await api.importPreview('version = 1\n');
    expect(res.data?.routes.added).toHaveLength(1);
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/config/import/preview',
      expect.objectContaining({ method: 'POST' }),
    );
  });
});

describe('api.importConfig', () => {
  it('calls POST /api/v1/config/import with toml_content', async () => {
    mockFetch({ message: 'configuration imported successfully' });
    const res = await api.importConfig('version = 1\n');
    expect(res.data?.message).toBe('configuration imported successfully');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/config/import',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ toml_content: 'version = 1\n' }),
      }),
    );
  });
});
