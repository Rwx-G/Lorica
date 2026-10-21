import { render, screen, waitFor, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { auth, type Role } from '../lib/auth';
import { clusterStatus, type ClusterStatus } from '../lib/cluster';
import { api, type AdcsAuthorityState, type ApiError, type CertificateResponse } from '../lib/api';
import { ADCS_RENEWAL_STILL_FINISHING } from '../lib/adcs-issuance';
import { testAuthority, testAuthorityState, testCertificate } from '../test-adcs-fixtures';
import Certificates from './Certificates.svelte';

const adcsCert = testCertificate('app.corp.example.org', [], {
  source: 'adcs',
  adcs_authority_id: 'adcs-1',
  adcs_template: 'LoricaWebServer',
});

function as(role: Role): void {
  auth.set({ status: 'authenticated', username: role, role });
}

function served(state: AdcsAuthorityState = testAuthorityState()) {
  return vi.spyOn(api, 'getAdcsAuthority').mockResolvedValue({ data: state });
}

async function rendered(certificates: CertificateResponse[] = [adcsCert]): Promise<void> {
  vi.spyOn(api, 'listCertificates').mockResolvedValue({ data: { certificates } });
  render(Certificates);
  await screen.findByRole('button', { name: certificates[0].domain });
  // Let the mount-time authority read settle before asserting absence.
  await new Promise((resolve) => setTimeout(resolve, 0));
}

const renewButton = () => screen.queryByRole('button', { name: 'Renew certificate from AD CS' });

async function confirmRenewal(): Promise<void> {
  const button = renewButton();
  expect(button).not.toBeNull();
  await fireEvent.click(button as HTMLElement);
  await fireEvent.click(screen.getByRole('button', { name: 'Renew now' }));
}

beforeEach(() => {
  vi.restoreAllMocks();
  as('operator');
  clusterStatus.set(null);
  vi.spyOn(api, 'listRoutes').mockResolvedValue({ data: { routes: [] } });
  vi.spyOn(api, 'listDnsProviders').mockResolvedValue({ data: { dns_providers: [] } });
  vi.spyOn(api, 'getSettings').mockResolvedValue({ error: { code: 'unknown', message: 'not under test' } });
  vi.spyOn(api, 'listPreferences').mockResolvedValue({ error: { code: 'unknown', message: 'not under test' } });
});

afterEach(() => {
  auth.set({ status: 'unauthenticated' });
  clusterStatus.set(null);
});

describe('Certificates AD CS "Renew now" gating', () => {
  it('offers it to an Operator on the control plane with a healthy authority', async () => {
    served();
    await rendered();
    await waitFor(() => expect(renewButton()).toBeInTheDocument());
  });

  it('hides it while the authority is in the failed state', async () => {
    served(testAuthorityState({ authority: testAuthority({ failed_since: '2026-10-20T08:00:00Z' }) }));
    await rendered();
    expect(renewButton()).not.toBeInTheDocument();
  });

  it('hides it when no authority is configured', async () => {
    served({ authority: null, managed_on_control_plane: false });
    await rendered();
    expect(renewButton()).not.toBeInTheDocument();
  });

  it('hides it on a follower, by the API flag', async () => {
    served({ authority: testAuthority(), managed_on_control_plane: true });
    await rendered();
    expect(renewButton()).not.toBeInTheDocument();
  });

  it('hides it on a follower in break-glass, without reading the authority', async () => {
    clusterStatus.set({
      role: 'follower',
      break_glass_until: new Date(Date.now() + 3_600_000).toISOString(),
    } as ClusterStatus);
    const get = served();
    await rendered();
    expect(renewButton()).not.toBeInTheDocument();
    expect(get).not.toHaveBeenCalled();
  });

  it('hides it from a Viewer, without reading the authority', async () => {
    as('viewer');
    const get = served();
    await rendered();
    expect(renewButton()).not.toBeInTheDocument();
    expect(get).not.toHaveBeenCalled();
  });
});

describe('Certificates AD CS "Renew now" outcomes', () => {
  it('asks for confirmation and sends nothing on cancel', async () => {
    served();
    const renew = vi.spyOn(api, 'renewCertificate');
    await rendered();
    await waitFor(() => expect(renewButton()).toBeInTheDocument());
    await fireEvent.click(renewButton() as HTMLElement);
    expect(screen.getByText(/template LoricaWebServer/)).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(renew).not.toHaveBeenCalled();
  });

  it('200: shows the subject as issued and the new expiry', async () => {
    served();
    const renewed = { ...adcsCert, subject: 'CN=app.corp.example.org,OU=IT,O=Example Corp,C=FR', not_after: '2027-10-21T00:00:00Z' };
    const renew = vi.spyOn(api, 'renewCertificate').mockResolvedValue({ data: renewed });
    await rendered();
    await waitFor(() => expect(renewButton()).toBeInTheDocument());
    await confirmRenewal();
    await waitFor(() => expect(screen.getByTestId('adcs-renew-outcome')).toHaveTextContent('Renewed app.corp.example.org'));
    expect(renew).toHaveBeenCalledWith(adcsCert.id);
    expect(screen.getByTestId('adcs-renew-outcome')).toHaveTextContent(renewed.subject);
    expect(screen.getByTestId('adcs-renew-outcome')).toHaveTextContent('Oct 21, 2027');
  });

  it('202: shows the request id and that nothing was stored', async () => {
    served();
    vi.spyOn(api, 'renewCertificate').mockResolvedValue({
      data: { outcome: 'pending', request_id: '4712', message: 'Taken under submission' },
    });
    await rendered();
    await waitFor(() => expect(renewButton()).toBeInTheDocument());
    await confirmRenewal();
    const outcome = await screen.findByTestId('adcs-renew-outcome');
    expect(outcome).toHaveTextContent('4712');
    expect(outcome).toHaveTextContent('Taken under submission');
    expect(outcome).toHaveTextContent('Nothing was stored');
  });

  const refusals: [string, ApiError, string][] = [
    ['409 in flight', { code: 'conflict', message: 'certificate `c`: a renewal is in flight', status: 409 }, 'a renewal is in flight'],
    ['409 busy', { code: 'adcs_busy', message: 'an AD CS operation is already running', status: 409 }, 'already running'],
    ['409 failed state', { code: 'adcs_failed_state', message: 'the AD CS authority is in the failed state', status: 409 }, 'failed state'],
    ['409 not configured', { code: 'adcs_not_configured', message: 'the AD CS authority has no password set', status: 409 }, 'no password set'],
    ['409 follower', { code: 'conflict', message: 'AD CS operations run on the control plane', status: 409 }, 'control plane'],
    ['422 denied', { code: 'adcs_denied', message: 'Denied by Policy Module 0x80094012', status: 422 }, 'Denied by Policy Module 0x80094012'],
    [
      '502 error',
      { code: 'adcs_error', message: 'the CA closed the connection', step: 'enroll', status: 502 },
      'the CA closed the connection (failing step: enroll)',
    ],
    [
      '504 still finishing',
      { code: 'parse_error', message: 'Server returned invalid response (504)', status: 504 },
      ADCS_RENEWAL_STILL_FINISHING,
    ],
  ];
  for (const [name, error, shown] of refusals) {
    it(`${name}: shows the answer`, async () => {
      served();
      vi.spyOn(api, 'renewCertificate').mockResolvedValue({ error });
      await rendered();
      await waitFor(() => expect(renewButton()).toBeInTheDocument());
      await confirmRenewal();
      const outcome = await screen.findByTestId('adcs-renew-outcome');
      expect(outcome).toHaveTextContent(shown);
      expect(outcome).toHaveAttribute('role', 'alert');
    });
  }

  it('re-reads the authority after a refusal and hides the action once it failed', async () => {
    const get = served();
    vi.spyOn(api, 'renewCertificate').mockResolvedValue({
      error: { code: 'adcs_error', message: 'kerberos: preauthentication failed', step: 'kerberos', status: 502 },
    });
    await rendered();
    await waitFor(() => expect(renewButton()).toBeInTheDocument());
    get.mockResolvedValue({
      data: testAuthorityState({ authority: testAuthority({ failed_since: '2026-10-21T08:00:00Z' }) }),
    });
    await confirmRenewal();
    await waitFor(() => expect(renewButton()).not.toBeInTheDocument());
    expect(get).toHaveBeenCalledTimes(2);
  });
});
