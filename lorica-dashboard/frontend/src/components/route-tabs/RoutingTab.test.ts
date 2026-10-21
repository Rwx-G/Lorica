import { render, screen, waitFor, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { auth, type Role } from '../../lib/auth';
import { clusterStatus, type ClusterStatus } from '../../lib/cluster';
import { api, type AdcsAuthorityState, type CertificateResponse } from '../../lib/api';
import { ROUTE_DEFAULTS, type RouteFormState } from '../../lib/route-form';
import { reactive } from '../../test-reactive.svelte';
import { testAuthority, testAuthorityState, testCertificate } from '../../test-adcs-fixtures';
import RoutingTab from './RoutingTab.svelte';

function as(role: Role): void {
  auth.set({ status: 'authenticated', username: role, role });
}

function routeForm(overrides: Partial<RouteFormState> = {}): RouteFormState {
  return reactive({
    ...ROUTE_DEFAULTS,
    backend_ids: [],
    hostname: 'app.corp.example.org',
    hostname_aliases: 'www.app.corp.example.org, *.corp.example.org',
    ...overrides,
  });
}

function served(state: AdcsAuthorityState = testAuthorityState()) {
  return vi.spyOn(api, 'getAdcsAuthority').mockResolvedValue({ data: state });
}

async function rendered(form: RouteFormState, certificates: CertificateResponse[] = []) {
  render(RoutingTab, { props: { form, backends: [], certificates } });
  // Let the mount-time authority read settle before asserting absence.
  await new Promise((resolve) => setTimeout(resolve, 0));
}

beforeEach(() => {
  vi.restoreAllMocks();
  as('operator');
  clusterStatus.set(null);
});

afterEach(() => {
  auth.set({ status: 'unauthenticated' });
  clusterStatus.set(null);
});

describe('RoutingTab AD CS offer', () => {
  it('names the uncovered hostnames, wildcard aliases dropped', async () => {
    served();
    await rendered(routeForm());
    const offer = await screen.findByTestId('adcs-route-offer');
    expect(offer).toHaveTextContent('app.corp.example.org, www.app.corp.example.org.');
    expect(offer).not.toHaveTextContent('*.corp.example.org');
  });

  it('counts every stored certificate, not only the selected one', async () => {
    served();
    await rendered(routeForm({ hostname_aliases: '' }), [
      testCertificate('other.corp.example.org', ['app.corp.example.org']),
    ]);
    expect(screen.queryByTestId('adcs-route-offer')).not.toBeInTheDocument();
  });

  it('is not offered when no authority is configured', async () => {
    served({ authority: null, managed_on_control_plane: false });
    await rendered(routeForm());
    expect(screen.queryByTestId('adcs-route-offer')).not.toBeInTheDocument();
  });

  it('is not offered while the authority is in the failed state', async () => {
    served(testAuthorityState({ authority: testAuthority({ failed_since: '2026-10-20T08:00:00Z' }) }));
    await rendered(routeForm());
    expect(screen.queryByTestId('adcs-route-offer')).not.toBeInTheDocument();
  });

  it('is not offered on a follower, by the API flag', async () => {
    served({ authority: null, managed_on_control_plane: true });
    await rendered(routeForm());
    expect(screen.queryByTestId('adcs-route-offer')).not.toBeInTheDocument();
  });

  it('is not offered on a follower, by the cluster role, and reads nothing', async () => {
    clusterStatus.set({ role: 'follower' } as ClusterStatus);
    const get = served();
    await rendered(routeForm());
    expect(screen.queryByTestId('adcs-route-offer')).not.toBeInTheDocument();
    expect(get).not.toHaveBeenCalled();
  });

  it('is not offered to a Viewer, and reads nothing', async () => {
    as('viewer');
    const get = served();
    await rendered(routeForm());
    expect(screen.queryByTestId('adcs-route-offer')).not.toBeInTheDocument();
    expect(get).not.toHaveBeenCalled();
  });
});

describe('RoutingTab AD CS issuance', () => {
  it('confirms the uncovered names, then selects the issued certificate', async () => {
    served();
    const issued = testCertificate('app.corp.example.org', ['app.corp.example.org', 'www.app.corp.example.org'], {
      id: 'cert-issued',
      source: 'adcs',
    });
    const issue = vi.spyOn(api, 'issueAdcsCertificate').mockResolvedValue({ data: issued });
    const list = vi.spyOn(api, 'listCertificates').mockResolvedValue({ data: { certificates: [issued] } });
    const form = routeForm();
    await rendered(form);

    await fireEvent.click(await screen.findByRole('button', { name: 'Issue from AD CS' }));
    const sans = screen.getByTestId('adcs-confirm-sans').querySelectorAll('li');
    expect([...sans].map((li) => li.textContent)).toEqual(['app.corp.example.org', 'www.app.corp.example.org']);
    expect(issue).not.toHaveBeenCalled();

    await fireEvent.click(screen.getByRole('button', { name: 'Issue' }));
    await waitFor(() => expect(form.certificate_id).toBe('cert-issued'));
    expect(issue.mock.calls[0][0]).toEqual({
      sans: ['app.corp.example.org', 'www.app.corp.example.org'],
      auto_renew: true,
    });
    expect(list).toHaveBeenCalled();
    await waitFor(() =>
      expect((document.getElementById('certificate') as HTMLSelectElement).value).toBe('cert-issued'),
    );
    expect(screen.getByTestId('adcs-route-outcome')).toHaveTextContent('once saved');
    expect(screen.getByTestId('adcs-route-outcome')).toHaveTextContent(
      'Subject as issued by the authority: CN=app.corp.example.org,O=Example Corp,C=FR',
    );
    expect(screen.queryByTestId('adcs-route-offer')).not.toBeInTheDocument();
  });

  it('keeps the selection resolvable when the list re-read fails', async () => {
    served();
    const issued = testCertificate('app.corp.example.org', [], { id: 'cert-issued', source: 'adcs' });
    vi.spyOn(api, 'issueAdcsCertificate').mockResolvedValue({ data: issued });
    vi.spyOn(api, 'listCertificates').mockResolvedValue({
      error: { code: 'network_error', message: 'Unable to reach the server.' },
    });
    const form = routeForm({ hostname_aliases: '' });
    await rendered(form);
    await fireEvent.click(await screen.findByRole('button', { name: 'Issue from AD CS' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Issue' }));
    await waitFor(() =>
      expect((document.getElementById('certificate') as HTMLSelectElement).value).toBe('cert-issued'),
    );
  });

  it('shows a pending answer inline and leaves the selection alone', async () => {
    served();
    vi.spyOn(api, 'issueAdcsCertificate').mockResolvedValue({
      data: { outcome: 'pending', request_id: '4711', message: 'Taken under submission' },
    });
    const form = routeForm();
    await rendered(form);
    await fireEvent.click(await screen.findByRole('button', { name: 'Issue from AD CS' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Issue' }));
    await waitFor(() => expect(screen.getByTestId('adcs-route-outcome')).toHaveTextContent('4711'));
    expect(form.certificate_id).toBe('');
  });

  it('shows a refusal verbatim inline', async () => {
    served();
    const message = 'names outside the allowed suffixes: www.app.corp.example.org';
    vi.spyOn(api, 'issueAdcsCertificate').mockResolvedValue({
      error: { code: 'adcs_san_refused', message, status: 422 },
    });
    await rendered(routeForm());
    await fireEvent.click(await screen.findByRole('button', { name: 'Issue from AD CS' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Issue' }));
    await waitFor(() => expect(screen.getByTestId('adcs-route-outcome')).toHaveTextContent(message));
  });
});
