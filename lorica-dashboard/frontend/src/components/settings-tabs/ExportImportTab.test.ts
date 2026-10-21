import { render, screen, waitFor, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { auth } from '../../lib/auth';
import { clusterStatus } from '../../lib/cluster';
import { api, type ImportDiffResponse } from '../../lib/api';
import ExportImportTab from './ExportImportTab.svelte';

const NO_CHANGE = { added: [], modified: [], removed: [] };

function diffAddingOneCertificate(): ImportDiffResponse {
  return {
    routes: NO_CHANGE,
    backends: NO_CHANGE,
    certificates: { added: ['example.com'], modified: [], removed: [] },
    route_backends: NO_CHANGE,
    notification_configs: NO_CHANGE,
    user_preferences: NO_CHANGE,
    users: NO_CHANGE,
    global_settings: { changes: [] },
  };
}

/// Drives the tab through file pick, preview and apply, with the apply
/// answering `warnings`.
async function importWith(warnings: string[]): Promise<void> {
  vi.spyOn(api, 'importPreview').mockResolvedValue({ data: diffAddingOneCertificate() });
  vi.spyOn(api, 'importConfig').mockResolvedValue({
    data: { message: 'configuration imported successfully', warnings },
  });
  const onReload = vi.fn().mockResolvedValue(undefined);
  const { container } = render(ExportImportTab, {
    props: { expanded: true, toggleSection: vi.fn(), onReload },
  });

  const input = container.querySelector('input[type="file"]') as HTMLInputElement;
  const file = new File(['version = 1\n'], 'lorica-config.toml', { type: 'text/plain' });
  await fireEvent.change(input, { target: { files: [file] } });
  await waitFor(() => expect(screen.getByRole('button', { name: 'Preview Changes' })).toBeEnabled());

  await fireEvent.click(screen.getByRole('button', { name: 'Preview Changes' }));
  await fireEvent.click(await screen.findByRole('button', { name: 'Apply Import' }));

  await screen.findByText('Configuration imported successfully.');
  expect(onReload).toHaveBeenCalledOnce();
}

beforeEach(() => {
  vi.restoreAllMocks();
  auth.set({ status: 'authenticated', username: 'admin', role: 'super_admin' });
  clusterStatus.set(null);
});

afterEach(() => {
  auth.set({ status: 'unauthenticated' });
  clusterStatus.set(null);
});

describe('ExportImportTab import warnings', () => {
  it('lists every warning next to the success message', async () => {
    const warnings = [
      'certificate example.com: AD CS authority absent on this node, imported as manual',
      'certificate api.example.com: AD CS authority absent on this node, imported as manual',
    ];
    await importWith(warnings);

    const alert = screen.getByRole('alert');
    const items = Array.from(alert.querySelectorAll('li')).map((li) => li.textContent);
    expect(items).toEqual(warnings);
  });

  it('shows no warning block when the import reports none', async () => {
    await importWith([]);

    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});
