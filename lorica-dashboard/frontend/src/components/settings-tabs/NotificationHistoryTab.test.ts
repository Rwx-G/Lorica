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

    for (const alertType of ['adcs_authority_failed', 'cert_issuance_failed']) {
      expect(screen.getByText(alertType)).toHaveClass('badge-red');
    }
  });
});
