import { render, screen, waitFor, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { auth } from '../../lib/auth';
import { clusterStatus, type ClusterStatus } from '../../lib/cluster';
import { api, type RouteProtectionRecord } from '../../lib/api';
import RouteProtectionRecordsTab from './RouteProtectionRecordsTab.svelte';

function record(overrides: Partial<RouteProtectionRecord> = {}): RouteProtectionRecord {
  return {
    id: 'rec-1',
    route_id: 'route-1',
    hostname: 'app.example.com',
    hostname_aliases: ['www.example.com'],
    path_prefix: '/api',
    deleted_by: 'ci pipeline (0123456789abcdef01234567)',
    deleted_at: '2026-11-04T10:00:00Z',
    controls: [
      { fields: ['ip_allowlist'], rule: 'added, or narrowed' },
      { fields: ['rate_limit', 'rate_limit_rps', 'rate_limit_burst'], rule: 'never removed' },
    ],
    readable: true,
    ...overrides,
  };
}

function props() {
  return { expanded: true, toggleSection: vi.fn() };
}

beforeEach(() => {
  vi.restoreAllMocks();
  auth.set({ status: 'authenticated', username: 'ops', role: 'operator' });
  clusterStatus.set(null);
});

afterEach(() => {
  auth.set({ status: 'unauthenticated' });
  clusterStatus.set(null);
});

describe('RouteProtectionRecordsTab listing', () => {
  it('shows what a record serves, who deleted it and the controls the server named', async () => {
    vi.spyOn(api, 'listRouteProtectionRecords').mockResolvedValue({
      data: { records: [record()] },
    });
    render(RouteProtectionRecordsTab, { props: props() });

    await waitFor(() => expect(screen.getByText('app.example.com')).toBeInTheDocument());
    expect(screen.getByText('www.example.com')).toBeInTheDocument();
    expect(screen.getByText('/api')).toBeInTheDocument();
    expect(screen.getByText('ci pipeline (0123456789abcdef01234567)')).toBeInTheDocument();
    // Each control renders as the server spelled it, its fields joined;
    // the tab holds no list of its own.
    for (const control of record().controls) {
      const badge = screen.getByText(control.fields.join(' / '));
      expect(badge).toHaveAttribute('title', control.rule);
    }
  });

  it('badges a record whose snapshot does not read', async () => {
    vi.spyOn(api, 'listRouteProtectionRecords').mockResolvedValue({
      data: { records: [record({ readable: false, controls: [] })] },
    });
    render(RouteProtectionRecordsTab, { props: props() });

    await waitFor(() => expect(screen.getByText('Unreadable')).toBeInTheDocument());
  });

  it('says so when there is no record, and shows a load failure', async () => {
    vi.spyOn(api, 'listRouteProtectionRecords').mockResolvedValue({ data: { records: [] } });
    const { unmount } = render(RouteProtectionRecordsTab, { props: props() });
    await waitFor(() =>
      expect(screen.getByText('No route protection records.')).toBeInTheDocument(),
    );
    unmount();

    vi.spyOn(api, 'listRouteProtectionRecords').mockResolvedValue({
      error: { code: 'forbidden', message: 'requires operator role', status: 403 },
    });
    render(RouteProtectionRecordsTab, { props: props() });
    await waitFor(() => expect(screen.getByText('requires operator role')).toBeInTheDocument());
  });
});

describe('RouteProtectionRecordsTab clear', () => {
  it('clears a record only after the confirmation, and drops it from the table', async () => {
    vi.spyOn(api, 'listRouteProtectionRecords').mockResolvedValue({
      data: { records: [record()] },
    });
    const clear = vi
      .spyOn(api, 'clearRouteProtectionRecord')
      .mockResolvedValue({ data: record() });
    render(RouteProtectionRecordsTab, { props: props() });

    await waitFor(() => expect(screen.getByRole('button', { name: 'Clear' })).toBeInTheDocument());
    await fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    expect(clear).not.toHaveBeenCalled();
    expect(screen.getByRole('dialog')).toHaveTextContent('app.example.com, www.example.com');

    await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(clear).not.toHaveBeenCalled();
    expect(screen.getByText('app.example.com')).toBeInTheDocument();

    await fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    const confirm = screen
      .getAllByRole('button', { name: 'Clear' })
      .find((button) => button.closest('[role="dialog"]') !== null);
    expect(confirm).toBeDefined();
    await fireEvent.click(confirm as HTMLElement);
    expect(clear).toHaveBeenCalledWith('rec-1');
    await waitFor(() =>
      expect(screen.getByText('No route protection records.')).toBeInTheDocument(),
    );
  });

  it('keeps the record when the server refuses the clear', async () => {
    vi.spyOn(api, 'listRouteProtectionRecords').mockResolvedValue({
      data: { records: [record()] },
    });
    vi.spyOn(api, 'clearRouteProtectionRecord').mockResolvedValue({
      error: { code: 'not_found', message: 'route protection record rec-1', status: 404 },
    });
    render(RouteProtectionRecordsTab, { props: props() });

    await waitFor(() => expect(screen.getByRole('button', { name: 'Clear' })).toBeInTheDocument());
    await fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    const confirm = screen
      .getAllByRole('button', { name: 'Clear' })
      .find((button) => button.closest('[role="dialog"]') !== null);
    await fireEvent.click(confirm as HTMLElement);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.getByText('app.example.com')).toBeInTheDocument();
  });

  it('offers no clear to a viewer or on a read-only follower', async () => {
    vi.spyOn(api, 'listRouteProtectionRecords').mockResolvedValue({
      data: { records: [record()] },
    });
    auth.set({ status: 'authenticated', username: 'viewer', role: 'viewer' });
    const { unmount } = render(RouteProtectionRecordsTab, { props: props() });
    await waitFor(() => expect(screen.getByText('app.example.com')).toBeInTheDocument());
    expect(screen.queryByRole('button', { name: 'Clear' })).not.toBeInTheDocument();
    unmount();

    // A follower refuses the clear outside a break-glass window.
    auth.set({ status: 'authenticated', username: 'ops', role: 'operator' });
    clusterStatus.set({ role: 'follower' } as ClusterStatus);
    render(RouteProtectionRecordsTab, { props: props() });
    await waitFor(() => expect(screen.getByText('app.example.com')).toBeInTheDocument());
    expect(screen.queryByRole('button', { name: 'Clear' })).not.toBeInTheDocument();
  });
});
