import { render, screen } from '@testing-library/svelte';
import { describe, it, expect, vi } from 'vitest';

import NotificationHistoryTab from './NotificationHistoryTab.svelte';

function event(alertType: string) {
  return {
    alert_type: alertType,
    summary: `${alertType} summary`,
    timestamp: '2026-10-21T00:00:00Z',
    details: {},
  };
}

describe('NotificationHistoryTab', () => {
  it('shows the AD CS failures as red badges, like the other failures', () => {
    render(NotificationHistoryTab, {
      props: {
        notifHistory: [event('adcs_authority_failed'), event('cert_issuance_failed')],
        expanded: true,
        toggleSection: vi.fn(),
      },
    });

    for (const label of ['AD CS authority failed', 'Certificate issuance failed']) {
      expect(screen.getByText(label)).toHaveClass('badge-red');
    }
  });

  it('follows the generated tone and shows an unknown type raw, in blue', () => {
    render(NotificationHistoryTab, {
      props: {
        notifHistory: [event('cluster_config_refused'), event('cluster_drift'), event('future_alert')],
        expanded: true,
        toggleSection: vi.fn(),
      },
    });

    expect(screen.getByText('Cluster configuration refused')).toHaveClass('badge-red');
    expect(screen.getByText('Cluster drift')).toHaveClass('badge-orange');
    expect(screen.getByText('future_alert')).toHaveClass('badge-blue');
  });
});
