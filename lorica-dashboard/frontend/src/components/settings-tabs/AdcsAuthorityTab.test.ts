import { render, screen, waitFor, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { auth, type Role } from '../../lib/auth';
import { clusterStatus, type ClusterStatus } from '../../lib/cluster';
import { api, type AdcsAuthority } from '../../lib/api';
import { ADCS_FAILURE_STEP_LABELS, ADCS_KDC_CODE_MEANINGS } from '../../lib/adcs.generated';
import { testAuthorityState } from '../../test-adcs-fixtures';
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
    allowed_templates: ['LoricaWebServer', 'LoricaWebServerEcdsa'],
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

let currentRole: Role = 'super_admin';

type Served = { authority?: AdcsAuthority | null; follower?: boolean; failedReason?: string | null };

/** The authority read as the API answers the current role: a Viewer gets the summary only (D18). */
function state({ authority: stored = authority(), follower = false, failedReason = null }: Served = {}) {
  return testAuthorityState({ authority: stored, follower, failedReason, viewer: currentRole === 'viewer' });
}

function served(options: Served = {}) {
  return vi.spyOn(api, 'getAdcsAuthority').mockResolvedValue({ data: state(options) });
}

function as(role: Role): void {
  currentRole = role;
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

  it('gives a Viewer the summary only: configured and the suffixes, no connection details (D18)', async () => {
    as('viewer');
    served();
    await rendered();
    const summary = screen.getByTestId('adcs-summary');
    expect(summary).toHaveTextContent('An AD CS authority is configured');
    expect(summary).toHaveTextContent('corp.example.org');
    expect(screen.queryByLabelText(/^CES endpoint/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^Kerberos realm/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^KDCs/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^Service principal/)).not.toBeInTheDocument();
    expect(document.body).not.toHaveTextContent('CORP-CA_CES_Kerberos');
    expect(document.body).not.toHaveTextContent('svc-lorica');
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
    served({ follower: true });
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
    as('operator');
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

describe('AdcsAuthorityTab issuing CA', () => {
  const PEM = ['-----BEGIN CERTIFICATE-----', 'MIIB', '-----END CERTIFICATE-----'].join('\n');

  async function saved(stored: string | null, typed?: string): Promise<Record<string, unknown>> {
    served({ authority: authority({ issuing_ca_pem: stored }) });
    const put = vi.spyOn(api, 'putAdcsAuthority').mockResolvedValue({ data: authority() });
    await rendered();
    if (typed !== undefined) {
      await fireEvent.input(screen.getByLabelText('Issuing CA certificate (PEM)'), { target: { value: typed } });
    }
    await fireEvent.click(screen.getByRole('button', { name: 'Save AD CS authority' }));
    await waitFor(() => expect(put).toHaveBeenCalled());
    return put.mock.calls[0][0] as unknown as Record<string, unknown>;
  }

  it('omits it when left empty, so a form loaded before the first issuance keeps what it learned', async () => {
    expect(await saved(null)).not.toHaveProperty('issuing_ca_pem');
  });

  it('omits it when left as loaded', async () => {
    expect(await saved(PEM)).not.toHaveProperty('issuing_ca_pem');
  });

  it('sends a pasted one', async () => {
    expect(await saved(null, PEM)).toHaveProperty('issuing_ca_pem', PEM);
  });

  it('sends a blank one when the operator clears it', async () => {
    expect(await saved(PEM, '  ')).toHaveProperty('issuing_ca_pem', '');
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

  it('shows a refused delete without an authority as the API words it', async () => {
    served();
    const message = 'no AD CS authority is configured';
    vi.spyOn(api, 'deleteAdcsAuthority').mockResolvedValue({
      error: { code: 'adcs_not_configured', message, status: 409 },
    });
    await rendered();
    await fireEvent.click(screen.getByRole('button', { name: 'Delete authority' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(screen.getByTestId('adcs-delete-error')).toHaveTextContent(message));
  });

  it('shows a busy save as the API words it', async () => {
    served();
    const message = 'an AD CS operation is already running; try again once it has finished';
    vi.spyOn(api, 'putAdcsAuthority').mockResolvedValue({
      error: { code: 'adcs_busy', message, status: 409 },
    });
    await rendered();
    await fireEvent.click(screen.getByRole('button', { name: 'Save AD CS authority' }));
    await waitFor(() => expect(screen.getByTestId('adcs-form-error')).toHaveTextContent(message));
  });

  it('names the step of a krb5.conf that could not be written', async () => {
    served();
    vi.spyOn(api, 'putAdcsAuthority').mockResolvedValue({
      error: {
        code: 'adcs_krb5_conf',
        message: 'the generated krb5.conf could not be written; the log names the path and the cause',
        step: 'krb5_conf',
        status: 500,
      },
    });
    await rendered();
    await fireEvent.click(screen.getByRole('button', { name: 'Save AD CS authority' }));
    await waitFor(() =>
      expect(screen.getByTestId('adcs-form-error')).toHaveTextContent(
        `(failing step: ${ADCS_FAILURE_STEP_LABELS.krb5_conf})`,
      ),
    );
  });

  it('shows a rate-limited test as such', async () => {
    served();
    vi.spyOn(api, 'testAdcsAuthority').mockResolvedValue({
      error: { code: 'rate_limited', message: 'rate limited (retry after 20s)', status: 429 },
    });
    await rendered();
    await fireEvent.click(screen.getByRole('button', { name: 'Test connection' }));
    await waitFor(() => expect(screen.getByTestId('adcs-test-error')).toHaveTextContent('Retry later'));
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

  it('shows a busy test verbatim', async () => {
    served();
    const message = 'an AD CS operation is already running; try again once it has finished';
    vi.spyOn(api, 'testAdcsAuthority').mockResolvedValue({
      error: { code: 'adcs_busy', message, status: 409 },
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
    await waitFor(() =>
      expect(screen.getByTestId('adcs-test-result')).toHaveTextContent(ADCS_FAILURE_STEP_LABELS.tls),
    );
    expect(screen.getByTestId('adcs-test-result')).toHaveTextContent('tls');
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
      data: state({
        authority: authority({
          failed_since: '2026-10-20T08:00:00Z',
          failed_step: 'ticket_acquisition',
          failed_kdc_code: 24,
        }),
      }),
    });
    await fireEvent.click(screen.getByRole('button', { name: 'Test connection' }));
    await waitFor(() => expect(screen.getByTestId('adcs-failed-state')).toBeInTheDocument());
    expect(get).toHaveBeenCalledTimes(2);
  });
});

describe('AdcsAuthorityTab failed state', () => {
  it('shows since, step, KDC code and the reason the API gives to every role, with how to clear it', async () => {
    as('viewer');
    served({
      authority: authority({
        failed_since: '2026-10-20T08:00:00Z',
        failed_step: 'ticket_acquisition',
        failed_kdc_code: 31,
      }),
      failedReason: 'integrity check on the decrypted field failed',
    });
    await rendered();
    const banner = screen.getByTestId('adcs-failed-state');
    expect(banner).toHaveTextContent(new Date('2026-10-20T08:00:00Z').toLocaleString());
    expect(banner).toHaveTextContent(ADCS_FAILURE_STEP_LABELS.ticket_acquisition);
    expect(banner).toHaveTextContent('ticket_acquisition');
    expect(banner).toHaveTextContent('31 (integrity check on the decrypted field failed)');
    expect(banner).toHaveTextContent('Saving a new password clears this state');
  });

  it('falls back on the generated meaning of a known code when the API gives no reason', async () => {
    served({
      authority: authority({
        failed_since: '2026-10-20T08:00:00Z',
        failed_step: 'ticket_acquisition',
        failed_kdc_code: 24,
      }),
    });
    await rendered();
    expect(screen.getByTestId('adcs-failed-state')).toHaveTextContent(`24 (${ADCS_KDC_CODE_MEANINGS[24]})`);
  });

  it('shows the code alone when the API gives no reason', async () => {
    served({
      authority: authority({
        failed_since: '2026-10-20T08:00:00Z',
        failed_step: 'ticket_acquisition',
        failed_kdc_code: 99,
      }),
    });
    await rendered();
    const banner = screen.getByTestId('adcs-failed-state');
    expect(banner).toHaveTextContent('99');
    expect(banner.textContent).not.toMatch(/99\s*\(/);
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

describe('AdcsAuthorityTab endpoint trust bundle', () => {
  it('asks for the password again when the endpoint CA bundle changes', async () => {
    served();
    const put = vi.spyOn(api, 'putAdcsAuthority');
    await rendered();
    await fireEvent.input(screen.getByLabelText(/^Endpoint CA bundle/), {
      target: { value: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----' },
    });
    expect(screen.getByTestId('adcs-identity-warning')).toHaveTextContent('endpoint CA bundle');
    await fireEvent.click(screen.getByRole('button', { name: 'Save AD CS authority' }));
    expect(screen.getByTestId('adcs-form-error')).toHaveTextContent('password must be entered again');
    expect(put).not.toHaveBeenCalled();
  });
});

describe('AdcsAuthorityTab allowed templates (D17)', () => {
  const list = () => screen.getByTestId('adcs-allowed-templates');

  it('lists the default as always allowed, with no way to remove it', async () => {
    served();
    await rendered();
    expect(list()).toHaveTextContent('LoricaWebServer');
    expect(list()).toHaveTextContent('default, always allowed');
    expect(screen.queryByRole('button', { name: 'Remove template LoricaWebServer' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Remove template LoricaWebServerEcdsa' })).toBeInTheDocument();
  });

  it('saves the templates added and removed, never the default twice', async () => {
    served();
    const put = vi.spyOn(api, 'putAdcsAuthority').mockResolvedValue({ data: authority() });
    await rendered();
    await fireEvent.click(screen.getByRole('button', { name: 'Remove template LoricaWebServerEcdsa' }));
    await fireEvent.input(screen.getByLabelText('Template to allow'), { target: { value: 'LoricaInternal' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Allow template' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Save AD CS authority' }));
    await waitFor(() => expect(put).toHaveBeenCalled());
    expect(put.mock.calls[0][0].allowed_templates).toEqual(['LoricaInternal']);
    expect(put.mock.calls[0][0].default_template).toBe('LoricaWebServer');
  });

  it('refuses to add a template already allowed, ignoring case', async () => {
    served();
    await rendered();
    await fireEvent.input(screen.getByLabelText('Template to allow'), { target: { value: 'loricawebserver' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Allow template' }));
    expect(screen.getByRole('alert')).toHaveTextContent('loricawebserver is already allowed.');
    expect(screen.queryByRole('button', { name: 'Remove template loricawebserver' })).not.toBeInTheDocument();
  });

  it('shows the list read-only to an Operator', async () => {
    as('operator');
    served();
    await rendered();
    expect(list()).toHaveTextContent('LoricaWebServerEcdsa');
    expect(screen.queryByRole('button', { name: /^Remove template/ })).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Template to allow')).not.toBeInTheDocument();
  });
});

describe('AdcsAuthorityTab subject defaults', () => {
  it('fills and sends every subject field the shared label table names', async () => {
    served();
    const put = vi.spyOn(api, 'putAdcsAuthority').mockResolvedValue({ data: authority() });
    await rendered();
    expect((screen.getByLabelText('Organization (O)') as HTMLInputElement).value).toBe('Example Corp');
    expect(screen.getByLabelText('Country (C)')).toHaveAttribute('maxlength', '2');
    await fireEvent.input(screen.getByLabelText('Locality (L)'), { target: { value: 'Paris' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save AD CS authority' }));
    await waitFor(() => expect(put).toHaveBeenCalled());
    expect(put.mock.calls[0][0].subject).toEqual({
      country: 'FR',
      state: null,
      locality: 'Paris',
      organization: 'Example Corp',
      organizational_unit: null,
      email: null,
    });
  });
});

describe('AdcsAuthorityTab section header', () => {
  it('says whether the section is expanded', async () => {
    served();
    await rendered();
    expect(screen.getByRole('button', { name: 'AD CS authority' })).toHaveAttribute('aria-expanded', 'true');
  });
});
