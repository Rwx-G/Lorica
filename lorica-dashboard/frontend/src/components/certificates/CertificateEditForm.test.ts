import { render, screen, waitFor, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach } from 'vitest';

import { api, type CertificateResponse } from '../../lib/api';
import { testCertificate } from '../../test-adcs-fixtures';
import CertificateEditForm from './CertificateEditForm.svelte';

function rendered(editingCert: CertificateResponse) {
  const props = {
    editingCert,
    dnsProviders: [],
    onClose: vi.fn(),
    onReload: vi.fn().mockResolvedValue(undefined),
  };
  render(CertificateEditForm, { props });
  return props;
}

const adcsCert = testCertificate('app.corp.example.org', [], {
  source: 'adcs',
  adcs_authority_id: 'adcs-1',
  acme_auto_renew: true,
});

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('CertificateEditForm on an AD CS certificate', () => {
  it('locks the domain, certificate and key, and says why', () => {
    rendered(adcsCert);
    expect(screen.getByTestId('adcs-managed-notice')).toHaveTextContent('Revert it to manual first');
    expect(screen.getByLabelText('Domain')).toBeDisabled();
    expect(screen.getByLabelText(/Replace Certificate PEM/)).toBeDisabled();
    expect(screen.getByLabelText(/Replace Private Key PEM/)).toBeDisabled();
  });

  it('keeps auto-renew editable and sends it alone', async () => {
    const update = vi.spyOn(api, 'updateCertificate').mockResolvedValue({ data: adcsCert });
    const props = rendered(adcsCert);
    const autoRenew = screen.getByLabelText('Auto-renew');
    expect(autoRenew).toBeEnabled();
    expect(autoRenew).toBeChecked();
    await fireEvent.click(autoRenew);
    await fireEvent.click(screen.getByRole('button', { name: 'Update' }));
    await waitFor(() => expect(update).toHaveBeenCalledOnce());
    expect(update.mock.calls[0]).toEqual([adcsCert.id, { acme_auto_renew: false }]);
    await waitFor(() => expect(props.onReload).toHaveBeenCalledOnce());
  });

  it('shows a 409 from the API as returned', async () => {
    const message = 'the PEM, key and domain of an AD CS certificate are managed by the authority';
    vi.spyOn(api, 'updateCertificate').mockResolvedValue({
      error: { code: 'adcs_certificate_managed', message, status: 409 },
    });
    rendered(adcsCert);
    await fireEvent.click(screen.getByLabelText('Auto-renew'));
    await fireEvent.click(screen.getByRole('button', { name: 'Update' }));
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(message));
  });
});

describe('CertificateEditForm on other certificates', () => {
  it('leaves a manual certificate fully editable, with no auto-renew', () => {
    rendered(testCertificate('legacy.corp.example.org'));
    expect(screen.queryByTestId('adcs-managed-notice')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Domain')).toBeEnabled();
    expect(screen.getByLabelText(/Replace Private Key PEM/)).toBeEnabled();
    expect(screen.queryByLabelText('Auto-renew')).not.toBeInTheDocument();
  });

  it('keeps the auto-renew of an ACME certificate', () => {
    rendered(testCertificate('acme.example.com', [], { source: 'acme', is_acme: true, acme_auto_renew: true }));
    expect(screen.getByLabelText('Auto-renew')).toBeChecked();
    expect(screen.getByLabelText('Domain')).toBeEnabled();
  });

  it('moves focus into the dialog', () => {
    rendered(testCertificate('legacy.corp.example.org'));
    expect(screen.getByRole('dialog').contains(document.activeElement)).toBe(true);
  });
});
