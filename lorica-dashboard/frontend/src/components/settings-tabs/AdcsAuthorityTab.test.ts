import { render, screen, waitFor, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { auth, type Role } from '../../lib/auth';
import { clusterStatus, type ClusterStatus } from '../../lib/cluster';
import { api, type AdcsAuthority, type AdcsAuthorityState } from '../../lib/api';
import AdcsAuthorityTab from './AdcsAuthorityTab.svelte';

function authority(overrides: Partial<AdcsAuthority> = {}): AdcsAuthority {
  return {
    id: 'adcs-1',
    endpoint: 'https://ces.corp.example.org/CORP-CA_CES_Kerberos/service.svc/CES',
    realm: 'CORP.EXAMPLE.ORG',
    kdcs: ['dc01.corp.example.org'],
    principal: 'svc-lorica',
    endpoint_ca_pem: null,
    issuing_ca_pem: null,
    default_template: 'LoricaWebServer',
    default_key_type: 'rsa2048',
    subject: {
      country: 'FR',
      state: null,
      locality: null,
      organization: 'Example Corp',
      organizational_unit: null,
      email: null,
    },
    allowed_suffixes: ['corp.example.org'],
    auto_renew_default: true,
    failed_since: null,
    failed_step: null,
    failed_kdc_code: null,
    created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-01T00:00:00Z',
    password_set: true,
    ...overrides,
  };
}

function served(state: Partial<AdcsAuthorityState> = {}) {
  return vi.spyOn(api, 'getAdcsAuthority').mockResolvedValue({
    data: { authority: authority(), managed_on_control_plane: false, ...state },
  });
}

function as(role: Role): void {
  auth.set({ status: 'authenticated', username: role, role });
}

function props() {
  return { expanded: true, toggleSection: vi.fn() };
}

async function rendered(): Promise<void> {
  render(AdcsAuthorityTab, { props: props() });
  await waitFor(() => expect(screen.queryByText('Loading...')).not.toBeInTheDocument());
}

beforeEach(() => {
  vi.restoreAllMocks();
  as('super_admin');
  clusterStatus.set(null);
});

afterEach(() => {
  auth.set({ status: 'unauthenticated' });
  clusterStatus.set(null);
});

describe('AdcsAuthorityTab roles', () => {
  it('gives a SuperAdmin the editable form, save, delete and the test', async () => {
    served();
    await rendered();
    expect(screen.getByLabelText(/^CES endpoint/)).toBeEnabled();
    expect(screen.getByLabelText(/^Service account password/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save AD CS authority' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete authority' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Test connection' })).toBeInTheDocument();
  });

  it('gives an Operator a read-only view and the connection test', async () => {
    // Writes are SuperAdmin server-side (D11); the test is carved out
    // at Operator.
    as('operator');
    served();
    await rendered();
    const endpoint = screen.getByLabelText(/^CES endpoint/) as HTMLInputElement;
    expect(endpoint).toBeDisabled();
    expect(endpoint.value).toBe(authority().endpoint);
    expect(screen.queryByLabelText(/^Service account password/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save AD CS authority' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Delete authority' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Test connection' })).toBeInTheDocument();
  });

  it('gives a Viewer the read-only view without the test', async () => {
    as('viewer');
    served();
    await rendered();
    expect(screen.getByLabelText(/^Allowed DNS suffixes/)).toBeDisabled();
    expect(screen.queryByRole('button', { name: 'Test connection' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save AD CS authority' })).not.toBeInTheDocument();
  });

  it('tells a reader with no authority that none is configured', async () => {
    as('viewer');
    served({ authority: null });
    await rendered();
    expect(screen.getByText('No AD CS authority is configured.')).toBeInTheDocument();
  });
});

describe('AdcsAuthorityTab on a follower', () => {
  it('shows the control-plane notice and nothing to write or test, on the API flag', async () => {
    served({ authority: null, managed_on_control_plane: true });
    await rendered();
    expect(screen.getByTestId('adcs-follower-notice')).toHaveTextContent(
      'managed on the control plane',
    );
    expect(screen.queryByLabelText(/^CES endpoint/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save AD CS authority' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Test connection' })).not.toBeInTheDocument();
  });

  it('treats the cluster role as a follower even inside a break-glass window', async () => {
    // Break-glass reopens `isSuperAdmin`, but the AD CS handlers refuse
    // on a follower regardless, so the tab must not offer them.
    clusterStatus.set({
      role: 'follower',
      break_glass_until: new Date(Date.now() + 3_600_000).toISOString(),
    } as ClusterStatus);
    served();
    await rendered();
    expect(screen.getByTestId('adcs-follower-notice')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save AD CS authority' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Test connection' })).not.toBeInTheDocument();
  });
});

describe('AdcsAuthorityTab password', () => {
  it('reports the stored password as set or not set and never fills the field', async () => {
    served();
    await rendered();
    expect(screen.getByTestId('adcs-password-state')).toHaveTextContent(/^set$/);
    expect((screen.getByLabelText(/^Service account password/) as HTMLInputElement).value).toBe('');
  });

  it('says not set when no password is stored', async () => {
    as('viewer');
    served({ authority: authority({ password_set: false }) });
    await rendered();
    expect(screen.getByTestId('adcs-password-state')).toHaveTextContent('not set');
  });

  it('omits the password from an update that does not change it', async () => {
    served();
    const put = vi.spyOn(api, 'putAdcsAuthority').mockResolvedValue({ data: authority() });
    await rendered();
    await fireEvent.click(screen.getByRole('button', { name: 'Save AD CS authority' }));
    await waitFor(() => expect(put).toHaveBeenCalled());
    expect(put.mock.calls[0][0]).not.toHaveProperty('password');
  });

  it('warns that an identity change needs the password again, and does not send without it', async () => {
    served();
    const put = vi.spyOn(api, 'putAdcsAuthority');
    await rendered();
    expect(screen.queryByTestId('adcs-identity-warning')).not.toBeInTheDocument();

    await fireEvent.input(screen.getByLabelText(/^Kerberos realm/), {
      target: { value: 'OTHER.EXAMPLE.ORG' },
    });
    expect(screen.getByTestId('adcs-identity-warning')).toHaveTextContent(
      'password must be entered again',
    );

    await fireEvent.click(screen.getByRole('button', { name: 'Save AD CS authority' }));
    expect(screen.getByTestId('adcs-form-error')).toHaveTextContent('password must be entered again');
    expect(put).not.toHaveBeenCalled();
  });

  it('sends the new password with an identity change', async () => {
    served();
    const put = vi.spyOn(api, 'putAdcsAuthority').mockResolvedValue({ data: authority() });
    await rendered();
    await fireEvent.input(screen.getByLabelText(/^Service principal/), {
      target: { value: 'svc-other' },
    });
    await fireEvent.input(screen.getByLabelText(/^Service account password/), {
      target: { value: 'placeholder-password' },
    });
    await fireEvent.click(screen.getByRole('button', { name: 'Save AD CS authority' }));
    await waitFor(() => expect(put).toHaveBeenCalled());
    expect(put.mock.calls[0][0]).toMatchObject({
      principal: 'svc-other',
      password: 'placeholder-password',
    });
  });
});

describe('AdcsAuthorityTab refusals', () => {
  it('shows a 422 from the API verbatim', async () => {
    served();
    const message = 'allowed_suffixes: wildcards are refused';
    vi.spyOn(api, 'putAdcsAuthority').mockResolvedValue({
      error: { code: 'unprocessable_entity', message, status: 422 },
    });
    await rendered();
    await fireEvent.click(screen.getByRole('button', { name: 'Save AD CS authority' }));
    await waitFor(() => expect(screen.getByTestId('adcs-form-error')).toHaveTextContent(message));
  });

  it('shows the 409 certificate list of a refused delete', async () => {
    served();
    const message =
      'the AD CS authority is used by certificates cert-1, cert-2; revert them to manual or delete them first';
    vi.spyOn(api, 'deleteAdcsAuthority').mockResolvedValue({
      error: { code: 'conflict', message, status: 409 },
    });
    await rendered();
    await fireEvent.click(screen.getByRole('button', { name: 'Delete authority' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(screen.getByTestId('adcs-delete-error')).toHaveTextContent(message));
  });

  it('shows a 409 from the test verbatim', async () => {
    served();
    const message = 'an AD CS operation is already running; try again once it has finished';
    vi.spyOn(api, 'testAdcsAuthority').mockResolvedValue({
      error: { code: 'conflict', message, status: 409 },
    });
    await rendered();
    await fireEvent.click(screen.getByRole('button', { name: 'Test connection' }));
    await waitFor(() => expect(screen.getByTestId('adcs-test-error')).toHaveTextContent(message));
  });

  it('reads a 504 as an operation still finishing, whatever the body says', async () => {
    served();
    vi.spyOn(api, 'testAdcsAuthority').mockResolvedValue({
      error: { code: 'parse_error', message: 'Server returned invalid response (504)', status: 504 },
    });
    await rendered();
    await fireEvent.click(screen.getByRole('button', { name: 'Test connection' }));
    await waitFor(() =>
      expect(screen.getByTestId('adcs-test-error')).toHaveTextContent(
        'still finishing on the server. Retry shortly.',
      ),
    );
  });
});

describe('AdcsAuthorityTab connection test', () => {
  it('reports success', async () => {
    served();
    vi.spyOn(api, 'testAdcsAuthority').mockResolvedValue({
      data: { ok: true, step: null, message: null, authority_failed: false },
    });
    await rendered();
    await fireEvent.click(screen.getByRole('button', { name: 'Test connection' }));
    await waitFor(() =>
      expect(screen.getByTestId('adcs-test-result')).toHaveTextContent('Connection OK'),
    );
  });

  it('names the failing step and shows the message as returned', async () => {
    served();
    const message = 'TLS handshake with the CES endpoint failed: unknown issuer';
    vi.spyOn(api, 'testAdcsAuthority').mockResolvedValue({
      data: { ok: false, step: 'tls', message, authority_failed: false },
    });
    await rendered();
    await fireEvent.click(screen.getByRole('button', { name: 'Test connection' }));
    await waitFor(() => expect(screen.getByTestId('adcs-test-result')).toHaveTextContent('tls'));
    expect(screen.getByTestId('adcs-test-result')).toHaveTextContent(message);
  });

  it('reads the authority back when the test opened the breaker', async () => {
    const get = served();
    vi.spyOn(api, 'testAdcsAuthority').mockResolvedValue({
      data: {
        ok: false,
        step: 'ticket_acquisition',
        message: 'the KDC rejected the credential',
        authority_failed: true,
      },
    });
    await rendered();
    get.mockResolvedValue({
      data: {
        authority: authority({
          failed_since: '2026-10-20T08:00:00Z',
          failed_step: 'ticket_acquisition',
          failed_kdc_code: 24,
        }),
        managed_on_control_plane: false,
      },
    });
    await fireEvent.click(screen.getByRole('button', { name: 'Test connection' }));
    await waitFor(() => expect(screen.getByTestId('adcs-failed-state')).toBeInTheDocument());
    expect(get).toHaveBeenCalledTimes(2);
  });
});

describe('AdcsAuthorityTab failed state', () => {
  it('shows since, step and KDC code to every role, with how to clear it', async () => {
    as('viewer');
    served({
      authority: authority({
        failed_since: '2026-10-20T08:00:00Z',
        failed_step: 'ticket_acquisition',
        failed_kdc_code: 24,
      }),
    });
    await rendered();
    const banner = screen.getByTestId('adcs-failed-state');
    expect(banner).toHaveTextContent(new Date('2026-10-20T08:00:00Z').toLocaleString());
    expect(banner).toHaveTextContent('ticket_acquisition');
    expect(banner).toHaveTextContent('24 (wrong password)');
    expect(banner).toHaveTextContent('Saving a new password clears this state');
  });

  it('shows no banner while the authority is healthy', async () => {
    served();
    await rendered();
    expect(screen.queryByTestId('adcs-failed-state')).not.toBeInTheDocument();
  });
});

describe('AdcsAuthorityTab prerequisites', () => {
  it('lists the authority-side prerequisites in a collapsible section', async () => {
    as('viewer');
    served();
    await rendered();
    const summary = screen.getByText('Authority-side prerequisites');
    expect(summary.tagName).toBe('SUMMARY');
    const section = summary.closest('details');
    expect(section).toHaveTextContent('EDITF_ATTRIBUTESUBJECTALTNAME2');
    expect(section).toHaveTextContent('Extended Protection');
    expect(section).toHaveTextContent('docs/adcs.md');
  });
});
