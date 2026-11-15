import { render, screen, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { auth } from '../lib/auth';
import { api, type BackendResponse } from '../lib/api';
import { clusterStatus } from '../lib/cluster';
import {
  EXPECT_MAX_ALTERNATIVES,
  PROBE_TIMEOUT_MS_MAX,
  PROBE_TIMEOUT_MS_MIN,
  SEND_MAX_BYTES,
  TCP_CHECK_TEMPLATES,
} from '../lib/health-check-templates.generated';
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

  it('leaves the interval of a create to the server default unless one is typed', async () => {
    const create = vi.spyOn(api, 'createBackend').mockResolvedValue({ data: backend() });
    await openCreateForm();
    const interval = screen.getByLabelText('Health Check Interval (s)');
    expect(interval).toHaveValue(null);
    expect(interval).toHaveAttribute('placeholder', 'Default (Settings)');
    await fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    expect(create).toHaveBeenCalledTimes(1);
    // What reaches the server is the JSON body, where an undefined field is absent.
    expect(JSON.parse(JSON.stringify(create.mock.calls[0][0]))).not.toHaveProperty('health_check_interval_s');

    await fireEvent.click(screen.getByRole('button', { name: 'Add Backend' }));
    await fireEvent.input(screen.getByLabelText(/^Address/), { target: { value: '10.0.0.21:8080' } });
    await fireEvent.input(screen.getByLabelText('Health Check Interval (s)'), { target: { value: '15' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    expect(create).toHaveBeenCalledTimes(2);
    expect(create.mock.calls[1][0].health_check_interval_s).toBe(15);
  });

  it('sends the stored interval back on edit', async () => {
    const slow = backend({ id: 'backend-5', name: 'slow-01', health_check_interval_s: 45 });
    vi.spyOn(api, 'listBackends').mockResolvedValue({ data: { backends: [slow] } });
    const update = vi.spyOn(api, 'updateBackend').mockResolvedValue({ data: slow });
    render(Backends);
    await fireEvent.click(await screen.findByRole('button', { name: 'Edit slow-01' }));
    expect(screen.getByLabelText('Health Check Interval (s)')).toHaveValue(45);
    await fireEvent.click(screen.getByRole('button', { name: 'Update' }));
    expect(update.mock.calls[0][1].health_check_interval_s).toBe(45);
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

describe('Backends page: templates and send/expect checks (Story 12.7)', () => {
  async function openCreateFormOfKind(kind: string): Promise<void> {
    render(Backends);
    await screen.findByText('web-01');
    await fireEvent.click(screen.getByRole('button', { name: 'Add Backend' }));
    await fireEvent.input(screen.getByLabelText(/^Address/), { target: { value: '10.0.0.20:6379' } });
    await fireEvent.change(screen.getByLabelText('Health Check Type'), { target: { value: kind } });
  }

  it('offers every template of the catalogue, shows its bytes, and sends it by name', async () => {
    const create = vi.spyOn(api, 'createBackend').mockResolvedValue({ data: backend() });
    await openCreateFormOfKind('tcp_template');
    const select = screen.getByLabelText('Template');
    const offered = Array.from(select.querySelectorAll('option')).map((option) => option.value);
    expect(offered).toEqual(TCP_CHECK_TEMPLATES.map((template) => template.name));

    for (const template of TCP_CHECK_TEMPLATES) {
      await fireEvent.change(select, { target: { value: template.name } });
      const shown = screen.getByTestId('template-bytes');
      expect(shown).toHaveTextContent(template.summary);
      expect(shown).toHaveTextContent(template.send ? template.send.shown : 'Sends nothing');
      for (const answer of template.expect) {
        expect(shown).toHaveTextContent(`${answer.match} ${answer.bytes.shown}`);
      }
    }
    const last = TCP_CHECK_TEMPLATES[TCP_CHECK_TEMPLATES.length - 1];
    await fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    expect(create).toHaveBeenCalledTimes(1);
    expect(create.mock.calls[0][0].health_check).toEqual({ kind: 'tcp_template', template: last.name });
  });

  it('sends a custom check in its typed shape, text escapes decoded and hex as typed', async () => {
    const create = vi.spyOn(api, 'createBackend').mockResolvedValue({ data: backend() });
    await openCreateFormOfKind('tcp_send_expect');
    await fireEvent.input(screen.getByLabelText('Send'), { target: { value: 'PING\\r\\n' } });
    await fireEvent.input(screen.getByLabelText('Answer 1 bytes'), { target: { value: '+PONG' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Add an answer' }));
    await fireEvent.change(screen.getByLabelText('Answer 2 match'), { target: { value: 'contains' } });
    await fireEvent.change(screen.getByLabelText('Answer 2 encoding'), { target: { value: 'hex' } });
    await fireEvent.input(screen.getByLabelText('Answer 2 bytes'), { target: { value: '2d4e4f41555448' } });
    await fireEvent.input(screen.getByLabelText('Probe Timeout (ms)'), { target: { value: '2000' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    expect(create).toHaveBeenCalledTimes(1);
    expect(create.mock.calls[0][0].health_check).toEqual({
      kind: 'tcp_send_expect',
      send: { text: 'PING\r\n' },
      expect: [
        { match: 'prefix', bytes: { text: '+PONG' } },
        { match: 'contains', bytes: { hex: '2d4e4f41555448' } },
      ],
      timeout_ms: 2000,
    });
  });

  it('leaves send out when it is empty and stops adding answers at the limit', async () => {
    const create = vi.spyOn(api, 'createBackend').mockResolvedValue({ data: backend() });
    await openCreateFormOfKind('tcp_send_expect');
    await fireEvent.input(screen.getByLabelText('Answer 1 bytes'), { target: { value: '220' } });
    const add = screen.getByRole('button', { name: 'Add an answer' });
    for (let n = 1; n < EXPECT_MAX_ALTERNATIVES; n++) await fireEvent.click(add);
    expect(add).toBeDisabled();
    for (let n = 2; n <= EXPECT_MAX_ALTERNATIVES; n++) {
      await fireEvent.click(screen.getByRole('button', { name: 'Remove answer 2' }));
    }
    expect(screen.queryByLabelText('Answer 2 bytes')).toBeNull();
    await fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    expect(create.mock.calls[0][0].health_check).toEqual({
      kind: 'tcp_send_expect',
      expect: [{ match: 'prefix', bytes: { text: '220' } }],
    });
  });

  it('refuses what the server would before sending anything', async () => {
    const create = vi.spyOn(api, 'createBackend').mockResolvedValue({ data: backend() });
    await openCreateFormOfKind('tcp_send_expect');
    const answer = screen.getByLabelText('Answer 1 bytes');
    const submit = () => fireEvent.click(screen.getByRole('button', { name: 'Create' }));

    await fireEvent.change(screen.getByLabelText('Answer 1 encoding'), { target: { value: 'hex' } });
    await fireEvent.input(answer, { target: { value: 'abc' } });
    await submit();
    expect(screen.getByText('Answer 1 must be an even number of hexadecimal digits')).toBeInTheDocument();

    await fireEvent.change(screen.getByLabelText('Answer 1 encoding'), { target: { value: 'text' } });
    await fireEvent.input(answer, { target: { value: '' } });
    await submit();
    expect(screen.getByText(/^Answer 1 is empty/)).toBeInTheDocument();

    await fireEvent.input(answer, { target: { value: '+PONG' } });
    await fireEvent.input(screen.getByLabelText('Send'), { target: { value: 'a'.repeat(SEND_MAX_BYTES + 1) } });
    await submit();
    expect(screen.getByText(`Send is ${SEND_MAX_BYTES + 1} bytes, above the limit of ${SEND_MAX_BYTES}`)).toBeInTheDocument();

    await fireEvent.input(screen.getByLabelText('Send'), { target: { value: 'PING\\q' } });
    await submit();
    expect(screen.getByText(/^Send has an unknown escape/)).toBeInTheDocument();

    await fireEvent.input(screen.getByLabelText('Send'), { target: { value: '' } });
    await fireEvent.input(screen.getByLabelText('Probe Timeout (ms)'), { target: { value: String(PROBE_TIMEOUT_MS_MAX + 1) } });
    await submit();
    expect(screen.getByText(`Probe timeout must be between ${PROBE_TIMEOUT_MS_MIN} and ${PROBE_TIMEOUT_MS_MAX} ms`)).toBeInTheDocument();
    expect(create).not.toHaveBeenCalled();
  });

  it('refuses a plaintext exchange on a TLS upstream', async () => {
    const create = vi.spyOn(api, 'createBackend').mockResolvedValue({ data: backend() });
    await openCreateFormOfKind('tcp_template');
    await fireEvent.click(screen.getByLabelText(/^TLS upstream/));
    await fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    expect(create).not.toHaveBeenCalled();
    expect(screen.getByText(/speaks plaintext TCP/)).toBeInTheDocument();
  });

  it('badges a template by name and a custom check as send/expect', async () => {
    vi.spyOn(api, 'listBackends').mockResolvedValue({
      data: {
        backends: [
          backend({ id: 'b-t', name: 'redis-01', health_check: { kind: 'tcp_template', template: 'redis_ping' } }),
          backend({
            id: 'b-c',
            name: 'custom-01',
            health_check: { kind: 'tcp_send_expect', expect: [{ match: 'prefix', bytes: { text: '220' } }] },
          }),
        ],
      },
    });
    render(Backends);
    expect(await screen.findByText('TCP redis_ping')).toBeInTheDocument();
    expect(screen.getByText('TCP send/expect')).toBeInTheDocument();
  });

  for (const [what, send] of [
    ['a payload read in full', { text: 'AUTH s3cr3t\r\nPING\r\n' }],
    ['a payload read masked', { text: '[redacted]' }],
    ['a hex payload', { hex: '0000000804d2162f' }],
  ] as const) {
    it(`loads ${what} into the form and saves it back unchanged`, async () => {
      const stored = {
        kind: 'tcp_send_expect' as const,
        send,
        expect: [
          { match: 'contains' as const, bytes: { hex: '2b504f4e47' } },
          { match: 'prefix' as const, bytes: { text: 'back\\slash\t' } },
        ],
        timeout_ms: 1500,
      };
      const custom = backend({ id: 'b-c', name: 'custom-01', health_check: stored });
      vi.spyOn(api, 'listBackends').mockResolvedValue({ data: { backends: [custom] } });
      const update = vi.spyOn(api, 'updateBackend').mockResolvedValue({ data: custom });
      render(Backends);
      await fireEvent.click(await screen.findByRole('button', { name: 'Edit custom-01' }));
      expect(screen.getByLabelText('Health Check Type')).toHaveValue('tcp_send_expect');
      expect(screen.getByLabelText('Probe Timeout (ms)')).toHaveValue(1500);
      await fireEvent.click(screen.getByRole('button', { name: 'Update' }));
      expect(update).toHaveBeenCalledTimes(1);
      expect(update.mock.calls[0][1].health_check).toEqual(stored);
    });
  }
});
