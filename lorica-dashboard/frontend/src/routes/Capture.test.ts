import { render, screen } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { auth, type Role } from '../lib/auth';
import { api, type CaptureRuleResponse } from '../lib/api';
import { clusterStatus } from '../lib/cluster';
import Capture from './Capture.svelte';

function rule(overrides: Partial<CaptureRuleResponse> = {}): CaptureRuleResponse {
  return {
    id: 'cap-1',
    name: 'checkout 5xx',
    route_id: 'route-1',
    enabled: true,
    match: { source_cidrs: [], methods: [], path_prefix: null, path_regex: null, headers: [] },
    emit: { always: false, status: ['server_error'], min_latency_ms: null, upstream_error: false },
    capture: { request_body: true, response_body: true, request_body_max_bytes: 65536, response_body_max_bytes: 65536 },
    limits: { max_captures: 100, rate_per_minute: 10, ttl_seconds: 3600 },
    output: { dir: null, max_dir_bytes: null },
    redact: { headers: [], query: [] },
    created_by: 'admin',
    created_at: '2026-01-01T00:00:00Z',
    expires_at: '2999-01-01T00:00:00Z',
    captures_emitted: 7,
    captures_dropped: 1,
    ...overrides,
  };
}

function loginAs(role: Role) {
  auth.set({ status: 'authenticated', username: 'someone', role });
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api, 'listCaptureRules').mockResolvedValue({ data: { rules: [rule()] } });
  vi.spyOn(api, 'listRoutes').mockResolvedValue({
    data: { routes: [{ id: 'route-1', hostname: 'shop.example.com', path_prefix: '/' }] } as never,
  });
  vi.spyOn(api, 'listRecentCaptures').mockResolvedValue({ data: { captures: [], capacity: 50 } });
});

afterEach(() => {
  clusterStatus.set(null);
  auth.set({ status: 'unauthenticated' });
});

describe('Capture page role gating', () => {
  it('offers Disable to an Operator and never the create form', async () => {
    loginAs('operator');
    render(Capture);
    expect(await screen.findByRole('button', { name: 'Disable checkout 5xx' })).toBeInTheDocument();
    // The rules are loaded by now, so the absence of Edit is a gate
    // and not a race.
    expect(screen.queryByRole('button', { name: 'New rule' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Edit checkout 5xx' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Delete checkout 5xx' })).toBeNull();
  });

  it('offers Create, Edit and Delete to a SuperAdmin', async () => {
    loginAs('super_admin');
    render(Capture);
    // The header renders before the rules load; wait on a row control.
    expect(await screen.findByRole('button', { name: 'Edit checkout 5xx' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'New rule' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete checkout 5xx' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Disable checkout 5xx' })).toBeInTheDocument();
  });

  it('shows the counters, the remaining budget and the time to expiry', async () => {
    loginAs('operator');
    render(Capture);
    await screen.findByText('checkout 5xx');
    expect(screen.getByText('93 / 100')).toBeInTheDocument();
    expect(screen.getByText(/^in \d+d/)).toBeInTheDocument();
    expect(screen.getByText('Recording')).toBeInTheDocument();
  });

  it('marks a disabled rule and hides its Disable button', async () => {
    vi.spyOn(api, 'listCaptureRules').mockResolvedValue({ data: { rules: [rule({ enabled: false })] } });
    loginAs('operator');
    render(Capture);
    expect(await screen.findByText('Disabled')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Disable checkout 5xx' })).toBeNull();
  });
});
