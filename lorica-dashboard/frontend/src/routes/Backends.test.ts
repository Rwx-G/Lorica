import { render, screen, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { auth } from '../lib/auth';
import { api, type BackendResponse } from '../lib/api';
import { clusterStatus } from '../lib/cluster';
import Backends from './Backends.svelte';

function backend(overrides: Partial<BackendResponse> = {}): BackendResponse {
  return {
    id: 'backend-1',
    address: '10.0.0.10:8080',
    name: 'web-01',
    group_name: '',
    weight: 100,
    health_status: 'healthy',
    lifecycle_state: 'active',
    active_connections: 0,
    health_check_enabled: true,
    health_check_interval_s: 10,
    health_check_path: null,
    tls_upstream: false,
    tls_skip_verify: false,
    tls_sni: null,
    h2_upstream: false,
    ewma_score_us: 0,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

const managedBackend = backend({
  id: 'backend-2',
  address: '10.0.0.11:8080',
  name: 'pr-42-app',
  managed_by: { kind: 'automation', environment: 'pr-42' },
});

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api, 'listBackends').mockResolvedValue({ data: { backends: [backend(), managedBackend] } });
  auth.set({ status: 'authenticated', username: 'someone', role: 'operator' });
});

afterEach(() => {
  clusterStatus.set(null);
  auth.set({ status: 'unauthenticated' });
});

describe('Backends page: rows the automation API owns (Story 10.4 AC #8)', () => {
  it('badges a managed backend with its environment and not a plain one', async () => {
    render(Backends);
    await screen.findByText('pr-42-app');
    const badge = screen.getByTitle('Managed by the automation API for environment "pr-42"');
    expect(badge).toHaveTextContent('automation');
    expect(badge).toHaveTextContent('pr-42');
    expect(screen.getAllByText('automation')).toHaveLength(1);
  });

  it('disables Edit on a managed backend and leaves a plain one editable', async () => {
    render(Backends);
    const managedEdit = await screen.findByRole('button', { name: 'Edit pr-42-app' });
    expect(managedEdit).toBeDisabled();
    expect(managedEdit).toHaveAttribute(
      'title',
      'Managed by the automation API for environment "pr-42". Update it through the pipeline: the next PUT would overwrite a manual change.',
    );
    expect(screen.getByRole('button', { name: 'Edit web-01' })).toBeEnabled();
  });

  it('disables Delete on a managed backend and names the environment in the hint', async () => {
    render(Backends);
    const del = await screen.findByRole('button', { name: 'Delete pr-42-app' });
    expect(del).toBeDisabled();
    expect(del).toHaveAttribute(
      'title',
      'Managed by the automation API for environment "pr-42". Delete the environment, or update it through the pipeline: a backend removed by hand would be recreated by the next PUT.',
    );
    await fireEvent.click(del);
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.getByRole('button', { name: 'Delete web-01' })).toBeEnabled();
  });

  it('confirms a plain backend delete without mentioning an environment', async () => {
    render(Backends);
    await fireEvent.click(await screen.findByRole('button', { name: 'Delete web-01' }));
    expect(screen.getByRole('dialog')).not.toHaveTextContent('environment');
  });
});
