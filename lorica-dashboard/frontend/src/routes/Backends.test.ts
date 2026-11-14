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
    health_check: { kind: 'tcp_connect' },
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

describe('Backends page: the typed health check (Story 12.1 AC #3)', () => {
  async function openCreateForm(): Promise<void> {
    render(Backends);
    await screen.findByText('web-01');
    await fireEvent.click(screen.getByRole('button', { name: 'Add Backend' }));
    await fireEvent.input(screen.getByLabelText(/^Address/), { target: { value: '10.0.0.20:8080' } });
  }

  it('creates a backend with a TCP connect check by default, in the typed shape only', async () => {
    const create = vi.spyOn(api, 'createBackend').mockResolvedValue({ data: backend() });
    await openCreateForm();
    expect(screen.queryByLabelText(/^Health Check Path/)).toBeNull();
    await fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    expect(create).toHaveBeenCalledTimes(1);
    const body = create.mock.calls[0][0];
    expect(body.health_check).toEqual({ kind: 'tcp_connect' });
    expect(body).not.toHaveProperty('health_check_path');
  });

  it('creates a backend with an HTTP check of the path entered', async () => {
    const create = vi.spyOn(api, 'createBackend').mockResolvedValue({ data: backend() });
    await openCreateForm();
    await fireEvent.change(screen.getByLabelText('Health Check Type'), { target: { value: 'http' } });
    await fireEvent.input(screen.getByLabelText(/^Health Check Path/), { target: { value: '/healthz' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    expect(create).toHaveBeenCalledTimes(1);
    const body = create.mock.calls[0][0];
    expect(body.health_check).toEqual({ kind: 'http', path: '/healthz' });
    expect(body).not.toHaveProperty('health_check_path');
  });

  it('refuses an HTTP check without a path before sending anything', async () => {
    const create = vi.spyOn(api, 'createBackend').mockResolvedValue({ data: backend() });
    await openCreateForm();
    await fireEvent.change(screen.getByLabelText('Health Check Type'), { target: { value: 'http' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    expect(create).not.toHaveBeenCalled();
    expect(screen.getByText('An HTTP health check needs a path (e.g. /healthz)')).toBeInTheDocument();
  });

  it('edits a backend whose row only a legacy path described, and sends it back typed', async () => {
    // A row 1.10.6 wrote carries no typed definition; the API answers
    // it reconciled from the path, the deprecated field beside it.
    const legacy = backend({
      id: 'backend-3',
      name: 'legacy-01',
      health_check: { kind: 'http', path: '/legacy?deep=1' },
      health_check_path: '/legacy?deep=1',
    });
    vi.spyOn(api, 'listBackends').mockResolvedValue({ data: { backends: [legacy] } });
    const update = vi.spyOn(api, 'updateBackend').mockResolvedValue({ data: legacy });
    render(Backends);
    await screen.findByText('HTTP /legacy?deep=1');
    await fireEvent.click(screen.getByRole('button', { name: 'Edit legacy-01' }));
    expect(screen.getByLabelText('Health Check Type')).toHaveValue('http');
    expect(screen.getByLabelText(/^Health Check Path/)).toHaveValue('/legacy?deep=1');

    await fireEvent.click(screen.getByRole('button', { name: 'Update' }));
    expect(update).toHaveBeenCalledTimes(1);
    const [id, body] = update.mock.calls[0];
    expect(id).toBe('backend-3');
    expect(body.health_check).toEqual({ kind: 'http', path: '/legacy?deep=1' });
    expect(body).not.toHaveProperty('health_check_path');
  });

  it('switches an HTTP check to a TCP connect on edit', async () => {
    const http = backend({
      id: 'backend-4',
      name: 'http-01',
      health_check: { kind: 'http', path: '/ready' },
      health_check_path: '/ready',
    });
    vi.spyOn(api, 'listBackends').mockResolvedValue({ data: { backends: [http] } });
    const update = vi.spyOn(api, 'updateBackend').mockResolvedValue({ data: http });
    render(Backends);
    await fireEvent.click(await screen.findByRole('button', { name: 'Edit http-01' }));
    await fireEvent.change(screen.getByLabelText('Health Check Type'), { target: { value: 'tcp_connect' } });
    expect(screen.queryByLabelText(/^Health Check Path/)).toBeNull();
    await fireEvent.click(screen.getByRole('button', { name: 'Update' }));
    expect(update.mock.calls[0][1].health_check).toEqual({ kind: 'tcp_connect' });
  });
});
