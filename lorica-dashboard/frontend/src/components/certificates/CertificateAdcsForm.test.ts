import { render, screen, waitFor, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { auth, type Role } from '../../lib/auth';
import { clusterStatus, type ClusterStatus } from '../../lib/cluster';
import { api, type AdcsAuthorityState, type ApiError } from '../../lib/api';
import { ADCS_STILL_FINISHING } from '../../lib/adcs-issuance';
import { testAuthority, testAuthorityState, testCertificate } from '../../test-adcs-fixtures';
import CertificateAdcsForm from './CertificateAdcsForm.svelte';

function as(role: Role): void {
  auth.set({ status: 'authenticated', username: role, role });
}

function served(state: AdcsAuthorityState = testAuthorityState()) {
  return vi.spyOn(api, 'getAdcsAuthority').mockResolvedValue({ data: state });
}

async function rendered() {
  const props = { onClose: vi.fn(), onReload: vi.fn().mockResolvedValue(undefined), onView: vi.fn() };
  render(CertificateAdcsForm, { props });
  await waitFor(() =>
    expect(screen.queryByText('Loading the AD CS authority...')).not.toBeInTheDocument(),
  );
  return props;
}

async function reviewAndIssue(names: string): Promise<void> {
  await fireEvent.input(screen.getByLabelText(/^DNS names/), { target: { value: names } });
  await fireEvent.click(screen.getByRole('button', { name: 'Review request' }));
  await fireEvent.click(screen.getByRole('button', { name: 'Issue' }));
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

describe('CertificateAdcsForm availability', () => {
  it('offers the form with the authority defaults and the unbound note', async () => {
    served();
    await rendered();
    expect((screen.getByLabelText('Template') as HTMLInputElement).value).toBe('LoricaWebServer');
    expect((screen.getByLabelText('Organization (O)') as HTMLInputElement).value).toBe('Example Corp');
    expect(screen.getByLabelText('Auto-renew')).toBeChecked();
    expect(screen.getByTestId('adcs-unbound-note')).toHaveTextContent('once a route uses it');
  });

  it('explains instead of offering when no authority is configured', async () => {
    served({ authority: null, managed_on_control_plane: false });
    await rendered();
    expect(screen.getByTestId('adcs-issue-unavailable')).toHaveTextContent('No AD CS authority is configured');
    expect(screen.queryByRole('button', { name: 'Review request' })).not.toBeInTheDocument();
  });

  it('explains instead of offering while the authority is in the failed state', async () => {
    served(testAuthorityState({ authority: testAuthority({ failed_since: '2026-10-20T08:00:00Z' }) }));
    await rendered();
    expect(screen.getByTestId('adcs-issue-unavailable')).toHaveTextContent('failed state');
    expect(screen.queryByRole('button', { name: 'Review request' })).not.toBeInTheDocument();
  });

  it('explains instead of offering on a follower, by the API flag', async () => {
    served({ authority: null, managed_on_control_plane: true });
    await rendered();
    expect(screen.getByTestId('adcs-issue-unavailable')).toHaveTextContent('follower');
  });

  it('explains instead of offering on a follower, by the cluster role, even in break-glass', async () => {
    clusterStatus.set({
      role: 'follower',
      break_glass_until: new Date(Date.now() + 3_600_000).toISOString(),
    } as ClusterStatus);
    served();
    await rendered();
    expect(screen.getByTestId('adcs-issue-unavailable')).toHaveTextContent('follower');
    expect(screen.queryByRole('button', { name: 'Review request' })).not.toBeInTheDocument();
  });

  it('explains instead of offering to a Viewer', async () => {
    as('viewer');
    served();
    await rendered();
    expect(screen.getByTestId('adcs-issue-unavailable')).toHaveTextContent('Operator role');
    expect(screen.queryByRole('button', { name: 'Review request' })).not.toBeInTheDocument();
  });
});

describe('CertificateAdcsForm hints and request', () => {
  it('hints at wildcards and names outside the allowed suffixes without blocking', async () => {
    served();
    await rendered();
    await fireEvent.input(screen.getByLabelText(/^DNS names/), {
      target: { value: '*.corp.example.org\nevilcorp.example.org' },
    });
    expect(screen.getByTestId('adcs-hint-wildcard')).toHaveTextContent('*.corp.example.org');
    expect(screen.getByTestId('adcs-hint-suffix')).toHaveTextContent('evilcorp.example.org');
    await fireEvent.click(screen.getByRole('button', { name: 'Review request' }));
    expect(screen.getByTestId('adcs-issue-confirm')).toBeInTheDocument();
  });

  it('refuses to review an empty name list', async () => {
    served();
    const issue = vi.spyOn(api, 'issueAdcsCertificate');
    await rendered();
    await fireEvent.click(screen.getByRole('button', { name: 'Review request' }));
    expect(screen.getByRole('alert')).toHaveTextContent('Enter at least one DNS name.');
    expect(screen.queryByTestId('adcs-issue-confirm')).not.toBeInTheDocument();
    expect(issue).not.toHaveBeenCalled();
  });

  it('sends nothing before the confirmation, then only the changed overrides', async () => {
    served();
    const issue = vi
      .spyOn(api, 'issueAdcsCertificate')
      .mockResolvedValue({ data: testCertificate('app.corp.example.org', [], { source: 'adcs' }) });
    await rendered();
    await fireEvent.input(screen.getByLabelText(/^DNS names/), { target: { value: 'app.corp.example.org' } });
    await fireEvent.input(screen.getByLabelText('Organizational unit (OU)'), { target: { value: 'Web' } });
    await fireEvent.click(screen.getByLabelText('Auto-renew'));
    await fireEvent.click(screen.getByRole('button', { name: 'Review request' }));
    expect(issue).not.toHaveBeenCalled();
    await fireEvent.click(screen.getByRole('button', { name: 'Issue' }));
    await waitFor(() => expect(issue).toHaveBeenCalledOnce());
    expect(issue.mock.calls[0][0]).toEqual({
      sans: ['app.corp.example.org'],
      subject: { organizational_unit: 'Web' },
      auto_renew: false,
    });
  });
});

describe('CertificateAdcsForm outcomes', () => {
  it('201: shows the subject as issued, reloads, and links to it', async () => {
    served();
    const issued = testCertificate('app.corp.example.org', ['app.corp.example.org', 'www.app.corp.example.org'], {
      source: 'adcs',
      subject: 'CN=app.corp.example.org,OU=IT,O=Example Corp,C=FR',
    });
    vi.spyOn(api, 'issueAdcsCertificate').mockResolvedValue({ data: issued });
    const props = await rendered();
    await reviewAndIssue('app.corp.example.org\nwww.app.corp.example.org');
    await waitFor(() => expect(screen.getByTestId('adcs-issue-outcome')).toHaveTextContent('issued'));
    expect(screen.getByTestId('adcs-issued-subject')).toHaveTextContent(issued.subject);
    expect(props.onReload).toHaveBeenCalledOnce();
    await fireEvent.click(screen.getByRole('button', { name: 'View certificate' }));
    expect(props.onView).toHaveBeenCalledWith(issued);
  });

  it('201: says so when the returned subject is unreadable', async () => {
    served();
    vi.spyOn(api, 'issueAdcsCertificate').mockResolvedValue({
      data: testCertificate('app.corp.example.org', [], { source: 'adcs', subject: '' }),
    });
    await rendered();
    await reviewAndIssue('app.corp.example.org');
    await waitFor(() => expect(screen.getByTestId('adcs-issued-subject')).toHaveTextContent('not readable'));
  });

  it('202: shows the request id and message, and reloads nothing', async () => {
    served();
    vi.spyOn(api, 'issueAdcsCertificate').mockResolvedValue({
      data: { outcome: 'pending', request_id: '4711', message: 'Taken under submission' },
    });
    const props = await rendered();
    await reviewAndIssue('app.corp.example.org');
    await waitFor(() => expect(screen.getByTestId('adcs-issue-outcome')).toHaveTextContent('4711'));
    expect(screen.getByTestId('adcs-issue-outcome')).toHaveTextContent('Taken under submission');
    expect(screen.getByTestId('adcs-issue-outcome')).toHaveTextContent('Nothing was stored');
    expect(props.onReload).not.toHaveBeenCalled();
  });

  const refusals: [string, ApiError][] = [
    ['422 SAN refusal', { code: 'adcs_san_refused', message: 'names outside the allowed suffixes: evilcorp.example.org', status: 422 }],
    ['422 denial', { code: 'adcs_denied', message: 'Denied by Policy Module 0x80094012', status: 422 }],
    ['409 busy', { code: 'adcs_busy', message: 'an AD CS operation is already running', status: 409 }],
    ['502 error', { code: 'adcs_error', message: 'SPNEGO: missing mutual-authentication token', status: 502 }],
  ];
  for (const [name, error] of refusals) {
    it(`${name}: shows the API message verbatim`, async () => {
      served();
      vi.spyOn(api, 'issueAdcsCertificate').mockResolvedValue({ error });
      await rendered();
      await reviewAndIssue('app.corp.example.org');
      await waitFor(() => expect(screen.getByTestId('adcs-issue-outcome')).toHaveTextContent(error.message));
      expect(screen.getByRole('button', { name: 'Review request' })).toBeInTheDocument();
    });
  }

  it('504: says the issuance is still finishing', async () => {
    served();
    vi.spyOn(api, 'issueAdcsCertificate').mockResolvedValue({
      error: { code: 'parse_error', message: 'Server returned invalid response (504)', status: 504 },
    });
    await rendered();
    await reviewAndIssue('app.corp.example.org');
    await waitFor(() => expect(screen.getByTestId('adcs-issue-outcome')).toHaveTextContent(ADCS_STILL_FINISHING));
  });
});
