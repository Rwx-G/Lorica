import { render, screen, waitFor, fireEvent, within } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { auth } from '../../lib/auth';
import { clusterStatus } from '../../lib/cluster';
import { api, type SystemResponse, type UpgradePreview, type UpgradePreviewStream } from '../../lib/api';
import BinaryUpgradeTab from './BinaryUpgradeTab.svelte';

function stream(overrides: Partial<UpgradePreviewStream> = {}): UpgradePreviewStream {
  return {
    stream_id: 's-1',
    name: 'postgres',
    protocol: 'tcp',
    established: 3,
    on_upgrade: 'drain',
    drains_on_upgrade: false,
    ...overrides,
  };
}

function preview(overrides: Partial<UpgradePreview> = {}): UpgradePreview {
  return {
    drain_timeout_s: 120,
    handoff_available: true,
    previous_generation: null,
    streams: [],
    as_of: '2026-11-18T10:00:00Z',
    ...overrides,
  };
}

function served(answer: UpgradePreview) {
  return vi.spyOn(api, 'getUpgradePreview').mockResolvedValue({ data: answer });
}

/// Fill the form and open the confirm dialog, then wait for its preview.
async function openConfirm(): Promise<HTMLElement> {
  render(BinaryUpgradeTab, { props: { expanded: true, toggleSection: vi.fn() } });
  const binary = new File([new Uint8Array([1, 2, 3])], 'lorica');
  await fireEvent.change(screen.getByLabelText('Binary file'), { target: { files: [binary] } });
  await fireEvent.click(screen.getByLabelText('Paste hex'));
  await fireEvent.input(screen.getByLabelText('Signature (hex)'), {
    target: { value: 'f'.repeat(128) },
  });
  await fireEvent.click(screen.getByRole('button', { name: 'Verify & stage upgrade' }));
  const dialog = await screen.findByTestId('upgrade-confirm');
  await waitFor(() =>
    expect(within(dialog).queryByText(/Reading this node's open connections/)).not.toBeInTheDocument(),
  );
  return dialog;
}

beforeEach(() => {
  vi.restoreAllMocks();
  auth.set({ status: 'authenticated', username: 'admin', role: 'super_admin' });
  clusterStatus.set(null);
  vi.spyOn(api, 'getSystem').mockResolvedValue({
    data: { proxy: { version: '1.11.0', pid: 4100 } } as SystemResponse,
  });
});

afterEach(() => {
  auth.set({ status: 'unauthenticated' });
});

describe('BinaryUpgradeTab confirm dialog', () => {
  it('loads the preview when it opens and states the delay the response gives', async () => {
    const read = served(preview({ drain_timeout_s: 120 }));
    const dialog = await openConfirm();
    expect(read).toHaveBeenCalledTimes(1);
    expect(within(dialog).getByTestId('upgrade-drain')).toHaveTextContent('120 seconds');
    expect(document.body).not.toHaveTextContent(/30 seconds/);
  });

  it('shows no streams table for an empty stream list', async () => {
    served(preview({ streams: [] }));
    const dialog = await openConfirm();
    expect(within(dialog).queryByTestId('upgrade-streams')).not.toBeInTheDocument();
  });

  it('lists the streams holding connections and what the upgrade does to them', async () => {
    served(
      preview({
        drain_timeout_s: 300,
        streams: [
          stream({ stream_id: 's-1', name: 'postgres', established: 3, on_upgrade: 'drain' }),
          stream({ stream_id: 's-2', name: 'dns', protocol: 'udp', established: 2, on_upgrade: 'relay_in_flight' }),
          stream({ stream_id: 's-3', name: 'syslog', protocol: 'udp', established: 1, on_upgrade: 'close' }),
          stream({ stream_id: 's-4', name: 'idle-smtp', established: 0 }),
        ],
      }),
    );
    const dialog = await openConfirm();
    const rows = within(within(dialog).getByTestId('upgrade-streams')).getAllByRole('row').slice(1);
    const cells = rows.map((row) =>
      within(row)
        .getAllByRole('cell')
        .map((cell) => cell.textContent?.replace(/\s+/g, ' ').trim()),
    );
    expect(cells).toEqual([
      ['postgres TCP', '3', 'Served for up to 300 s, then closed'],
      ['dns UDP', '2', 'Owed responses relayed, then closed'],
      ['syslog UDP', '1', 'Closed at once'],
    ]);
  });

  it('warns when a previous generation is still draining, and only then', async () => {
    served(preview({ previous_generation: { pid: 4242 } }));
    const dialog = await openConfirm();
    expect(within(dialog).getByTestId('upgrade-previous-generation')).toHaveTextContent('PID 4242');
  });

  it('has no previous-generation warning without one', async () => {
    served(preview());
    const dialog = await openConfirm();
    expect(within(dialog).queryByTestId('upgrade-previous-generation')).not.toBeInTheDocument();
  });

  it('says a single-process node only stages the binary', async () => {
    served(preview({ handoff_available: false }));
    const dialog = await openConfirm();
    expect(within(dialog).getByTestId('upgrade-staged-only')).toBeInTheDocument();
    expect(within(dialog).queryByTestId('upgrade-drain')).not.toBeInTheDocument();
  });

  it('still lets the upgrade start when the preview cannot be read', async () => {
    vi.spyOn(api, 'getUpgradePreview').mockResolvedValue({
      error: { code: 'forbidden', message: 'requires super_admin role' },
    });
    const dialog = await openConfirm();
    expect(within(dialog).getByTestId('upgrade-preview-error')).toHaveTextContent('requires super_admin role');
    expect(within(dialog).getByRole('button', { name: 'Start upgrade' })).toBeEnabled();
  });
});
