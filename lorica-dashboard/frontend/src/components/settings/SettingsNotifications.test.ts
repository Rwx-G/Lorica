import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { auth } from '../../lib/auth';
import { clusterStatus } from '../../lib/cluster';
import { api, type NotificationConfigResponse } from '../../lib/api';
import SettingsNotifications from './SettingsNotifications.svelte';

function channel(alertTypes: string[]): NotificationConfigResponse {
  return {
    id: 'nc-1',
    channel: 'webhook',
    enabled: true,
    config: '{"url":"********"}',
    alert_types: alertTypes,
  };
}

function props(notifications: NotificationConfigResponse[]) {
  return {
    notifications,
    expandedSections: { notifications: true },
    toggleSection: vi.fn(),
    onReload: vi.fn().mockResolvedValue(undefined),
  };
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

describe('SettingsNotifications AD CS alert types', () => {
  it('reflects a stored subscription and saves both AD CS types once ticked', async () => {
    const update = vi
      .spyOn(api, 'updateNotification')
      .mockResolvedValue({ data: channel([]) });
    render(SettingsNotifications, { props: props([channel(['cert_issuance_failed'])]) });

    await fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
    const authority = screen.getByRole('checkbox', { name: 'AD CS authority failed' });
    const issuance = screen.getByRole('checkbox', { name: 'Certificate issuance failed' });
    expect(authority).not.toBeChecked();
    expect(issuance).toBeChecked();

    await fireEvent.click(authority);
    await fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update.mock.calls[0][1].alert_types).toEqual([
      'adcs_authority_failed',
      'cert_issuance_failed',
    ]);
  });

  it('includes both AD CS types in Select all', async () => {
    const create = vi
      .spyOn(api, 'createNotification')
      .mockResolvedValue({ data: channel([]) });
    render(SettingsNotifications, { props: props([]) });

    await fireEvent.click(screen.getByRole('button', { name: 'Add Channel' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Select all' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    const saved = create.mock.calls[0][0].alert_types;
    expect(saved).toContain('adcs_authority_failed');
    expect(saved).toContain('cert_issuance_failed');
  });

  it('leaves both AD CS types out when unticked', async () => {
    const update = vi
      .spyOn(api, 'updateNotification')
      .mockResolvedValue({ data: channel([]) });
    render(SettingsNotifications, { props: props([channel(['backend_down'])]) });

    await fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
    expect(screen.getByRole('checkbox', { name: 'AD CS authority failed' })).not.toBeChecked();
    expect(screen.getByRole('checkbox', { name: 'Certificate issuance failed' })).not.toBeChecked();
    await fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update.mock.calls[0][1].alert_types).toEqual(['backend_down']);
  });
});
