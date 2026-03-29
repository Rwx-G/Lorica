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
