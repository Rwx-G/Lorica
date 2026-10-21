import { render, screen, waitFor, fireEvent, within } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { auth, type Role } from '../lib/auth';
import { clusterStatus, type ClusterStatus } from '../lib/cluster';
import {
  api,
  type AdcsAdoptionCandidates,
  type AdcsAuthorityState,
  type ApiError,
  type CertificateResponse,
} from '../lib/api';
import { ADCS_KEY_NOT_EXPORTABLE_HINT, ADCS_RENEWAL_STILL_FINISHING } from '../lib/adcs-issuance';
import { ADCS_NO_ISSUING_CA_HINT } from '../lib/adcs-adoption';
import { testAuthority, testAuthorityState, testCandidate, testCertificate } from '../test-adcs-fixtures';
import { get } from 'svelte/store';
import { toasts } from '../lib/toast';
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
  offered({ reason: null, candidates: [] });
});

function offered(candidates: AdcsAdoptionCandidates) {
  return vi.spyOn(api, 'listAdcsAdoptionCandidates').mockResolvedValue({ data: candidates });
}

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
    served(testAuthorityState({ authority: null }));
    await rendered();
    expect(renewButton()).not.toBeInTheDocument();
  });

  it('hides it on a follower, by the API flag', async () => {
    served(testAuthorityState({ follower: true }));
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

const manualCert = testCertificate('legacy.corp.example.org');
const twoCandidates: AdcsAdoptionCandidates = {
  reason: null,
  candidates: [testCandidate('legacy.corp.example.org'), testCandidate('old.corp.example.org')],
};
const banner = () => screen.queryByTestId('adcs-adoption-banner');

describe('Certificates AD CS adoption banner', () => {
  it('announces the candidates to an Operator and opens the panel', async () => {
    served();
    offered(twoCandidates);
    await rendered([manualCert]);
    await waitFor(() =>
      expect(banner()).toHaveTextContent('2 certificates can be managed by the AD CS authority.'),
    );
    await fireEvent.click(screen.getByRole('button', { name: 'Review' }));
    expect(screen.getByTestId('adcs-adoption-panel')).toBeInTheDocument();
    expect(screen.getAllByTestId('adcs-adoption-candidate')).toHaveLength(2);
  });

  it('announces them to a SuperAdmin', async () => {
    as('super_admin');
    served();
    offered(twoCandidates);
    await rendered([manualCert]);
    await waitFor(() => expect(banner()).toBeInTheDocument());
  });

  it('hides it from a Viewer, without reading the candidates', async () => {
    as('viewer');
    served();
    const list = offered(twoCandidates);
    await rendered([manualCert]);
    expect(banner()).not.toBeInTheDocument();
    expect(list).not.toHaveBeenCalled();
  });

  it('hides it on a follower in break-glass, without reading the candidates', async () => {
    clusterStatus.set({
      role: 'follower',
      break_glass_until: new Date(Date.now() + 3_600_000).toISOString(),
    } as ClusterStatus);
    served();
    const list = offered(twoCandidates);
    await rendered([manualCert]);
    expect(banner()).not.toBeInTheDocument();
    expect(list).not.toHaveBeenCalled();
  });

  it('hides it on a follower, by the API flag', async () => {
    served(testAuthorityState({ follower: true }));
    offered(twoCandidates);
    await rendered([manualCert]);
    expect(banner()).not.toBeInTheDocument();
  });

  it('says how to provide the issuing CA when none is known', async () => {
    served();
    offered({ reason: 'no_issuing_ca', candidates: [] });
    await rendered([manualCert]);
    await waitFor(() => expect(banner()).toHaveTextContent(ADCS_NO_ISSUING_CA_HINT));
    expect(screen.queryByRole('button', { name: 'Review' })).not.toBeInTheDocument();
  });

  it('says nothing when no authority is configured', async () => {
    served(testAuthorityState({ authority: null }));
    offered({ reason: 'not_configured', candidates: [] });
    await rendered([manualCert]);
    expect(banner()).not.toBeInTheDocument();
  });

  it('re-reads the candidates after an adoption', async () => {
    served();
    const list = offered(twoCandidates);
    vi.spyOn(api, 'adoptAdcsCertificate').mockResolvedValue({ data: { ...manualCert, source: 'adcs' } });
    await rendered([manualCert]);
    await waitFor(() => expect(banner()).toBeInTheDocument());
    await fireEvent.click(screen.getByRole('button', { name: 'Review' }));
    list.mockResolvedValue({ data: { reason: null, candidates: [twoCandidates.candidates[1]] } });
    await fireEvent.click(screen.getByLabelText('Select legacy.corp.example.org'));
    await fireEvent.click(screen.getByRole('button', { name: 'Adopt selected (1)' }));
    await waitFor(() => expect(screen.getAllByTestId('adcs-adoption-candidate')).toHaveLength(1));
    expect(list).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId('adcs-adoption-results')).toHaveTextContent('legacy.corp.example.org: Adopted');
  });
});

const revertButton = () => screen.queryByRole('button', { name: 'Revert to manual' });

describe('Certificates AD CS "Revert to manual"', () => {
  it('is offered on AD CS certificates only', async () => {
    served();
    await rendered([adcsCert, manualCert]);
    await waitFor(() => expect(screen.getAllByRole('button', { name: 'Revert to manual' })).toHaveLength(1));
  });

  it('stays offered while the authority is in the failed state', async () => {
    served(testAuthorityState({ authority: testAuthority({ failed_since: '2026-10-20T08:00:00Z' }) }));
    await rendered();
    await waitFor(() => expect(revertButton()).toBeInTheDocument());
  });

  it('is hidden from a Viewer', async () => {
    as('viewer');
    served();
    await rendered();
    expect(revertButton()).not.toBeInTheDocument();
  });

  it('is hidden on a follower', async () => {
    served(testAuthorityState({ follower: true }));
    await rendered();
    expect(revertButton()).not.toBeInTheDocument();
  });

  it('explains the consequence and sends nothing on cancel', async () => {
    served();
    const revert = vi.spyOn(api, 'revertAdcsCertificate');
    await rendered();
    await waitFor(() => expect(revertButton()).toBeInTheDocument());
    await fireEvent.click(revertButton() as HTMLElement);
    expect(screen.getByText(/stops renewing it/)).toHaveTextContent('keeps the current certificate in service');
    await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(revert).not.toHaveBeenCalled();
  });

  it('reverts on confirmation and reloads the list', async () => {
    const reverted = { ...adcsCert, source: 'manual' as const, adcs_authority_id: null };
    served();
    const revert = vi.spyOn(api, 'revertAdcsCertificate').mockResolvedValue({ data: reverted });
    await rendered();
    await waitFor(() => expect(revertButton()).toBeInTheDocument());
    const list = vi.mocked(api.listCertificates);
    list.mockResolvedValue({ data: { certificates: [reverted] } });
    await fireEvent.click(revertButton() as HTMLElement);
    const dialog = screen.getByText(/stops renewing it/).closest('[role="document"]') as HTMLElement;
    await fireEvent.click(within(dialog).getByRole('button', { name: 'Revert to manual' }));
    expect(revert).toHaveBeenCalledWith(adcsCert.id);
    await waitFor(() => expect(revertButton()).not.toBeInTheDocument());
    expect(list).toHaveBeenCalledTimes(2);
  });
});

describe('Certificates download of an AD CS certificate (D16)', () => {
  async function openMenu(): Promise<HTMLElement> {
    await fireEvent.click(screen.getByRole('button', { name: 'Download certificate' }));
    return screen.getByRole('menu');
  }

  it('disables the key and the bundle with the reason, and keeps cert and chain', async () => {
    served();
    await rendered();
    const menu = await openMenu();
    expect(within(menu).getByRole('menuitem', { name: 'Bundle (cert + key)' })).toBeDisabled();
    expect(within(menu).getByRole('menuitem', { name: 'Private key (sensitive)' })).toBeDisabled();
    expect(within(menu).getByRole('menuitem', { name: 'Certificate only' })).toBeEnabled();
    expect(within(menu).getByRole('menuitem', { name: 'Certificate + chain' })).toBeEnabled();
    expect(within(menu).getByTestId('download-refusal')).toHaveTextContent(ADCS_KEY_NOT_EXPORTABLE_HINT);
  });

  it('downloads the chain of an AD CS certificate', async () => {
    served();
    const download = vi.spyOn(api, 'downloadCertificate').mockResolvedValue({ ok: true });
    await rendered();
    const menu = await openMenu();
    await fireEvent.click(within(menu).getByRole('menuitem', { name: 'Certificate + chain' }));
    expect(download).toHaveBeenCalledWith(adcsCert.id, 'chain');
  });

  it('offers every part of a manual certificate', async () => {
    served();
    await rendered([manualCert]);
    const menu = await openMenu();
    for (const item of within(menu).getAllByRole('menuitem')) expect(item).toBeEnabled();
    expect(within(menu).queryByTestId('download-refusal')).not.toBeInTheDocument();
  });

  it('shows the refusal of the API as returned', async () => {
    served();
    const message = 'the private key of an AD CS certificate never leaves Lorica';
    vi.spyOn(api, 'downloadCertificate').mockResolvedValue({ ok: false, message });
    await rendered([manualCert]);
    const menu = await openMenu();
    await fireEvent.click(within(menu).getByRole('menuitem', { name: 'Certificate only' }));
    await waitFor(() =>
      expect(get(toasts).map((toast) => toast.message)).toContain(`Download failed: ${message}`),
    );
  });
});

describe('Certificates delete dialog', () => {
  it('says that deleting an AD CS certificate does not revoke it', async () => {
    served();
    await rendered();
    await fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    expect(screen.getByRole('dialog')).toHaveTextContent('does not revoke it');
  });

  it('says nothing about revocation for a manual certificate', async () => {
    served();
    await rendered([manualCert]);
    await fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    expect(screen.getByRole('dialog')).not.toHaveTextContent('revoke');
  });
});

describe('Certificates reloads after a renewal', () => {
  it('re-reads the list but not the adoption candidates, which a renewal cannot change', async () => {
    served();
    const candidates = vi.mocked(api.listAdcsAdoptionCandidates);
    vi.spyOn(api, 'renewCertificate').mockResolvedValue({ data: adcsCert });
    await rendered();
    await waitFor(() => expect(renewButton()).toBeInTheDocument());
    const before = candidates.mock.calls.length;
    const list = vi.mocked(api.listCertificates);
    const listed = list.mock.calls.length;
    await confirmRenewal();
    await waitFor(() => expect(list.mock.calls.length).toBe(listed + 1));
    expect(candidates.mock.calls.length).toBe(before);
  });
});
