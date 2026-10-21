/**
 * Shared AD CS fixtures for the Vitest suites of Stories 13.3 to 13.5. A plain
 * module rather than an export of a test file, which would register
 * that file's suites a second time in every importer.
 */
import type {
  AdcsAdoptionCandidate,
  AdcsAuthority,
  AdcsAuthorityState,
  AdcsAuthoritySummary,
  CertificateResponse,
} from './lib/api';

export function testAuthority(overrides: Partial<AdcsAuthority> = {}): AdcsAuthority {
  return {
    id: 'adcs-1',
    endpoint: 'https://ces.corp.example.org/CORP-CA_CES_Kerberos/service.svc/CES',
    realm: 'CORP.EXAMPLE.ORG',
    kdcs: [],
    principal: 'svc-lorica',
    endpoint_ca_pem: null,
    issuing_ca_pem: null,
    default_template: 'LoricaWebServer',
    allowed_templates: ['LoricaWebServer'],
    default_key_type: 'rsa2048',
    subject: {
      country: 'FR',
      state: null,
      locality: 'Paris',
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

/** The summary the API derives from `authority` for every role. */
export function testSummary(
  authority: AdcsAuthority,
  failedReason: string | null = null,
): AdcsAuthoritySummary {
  return {
    allowed_suffixes: authority.allowed_suffixes,
    failed_since: authority.failed_since,
    failed_step: authority.failed_step,
    failed_kdc_code: authority.failed_kdc_code,
    failed_reason: failedReason,
  };
}

/**
 * A `GET /api/v1/adcs/authority` body shaped as the API builds it:
 * `authority: null` for none configured, `follower` for a follower
 * (which reports none), `viewer` for a Viewer (summary only, D18).
 */
export function testAuthorityState({
  authority = testAuthority(),
  follower = false,
  viewer = false,
  failedReason = null,
}: {
  authority?: AdcsAuthority | null;
  follower?: boolean;
  viewer?: boolean;
  failedReason?: string | null;
} = {}): AdcsAuthorityState {
  if (follower) return { configured: false, managed_on_control_plane: true, summary: null, authority: null };
  if (authority === null) return { configured: false, managed_on_control_plane: false, summary: null, authority: null };
  return {
    configured: true,
    managed_on_control_plane: false,
    summary: testSummary(authority, failedReason),
    authority: viewer ? null : authority,
  };
}

export function testCertificate(
  domain: string,
  san_domains: string[] = [],
  overrides: Partial<CertificateResponse> = {},
): CertificateResponse {
  return {
    id: `cert-${domain}`,
    domain,
    san_domains,
    fingerprint: 'ab',
    issuer: 'CN=Example Issuing CA',
    subject: `CN=${domain},O=Example Corp,C=FR`,
    not_before: '2026-01-01T00:00:00Z',
    not_after: '2027-01-01T00:00:00Z',
    is_acme: false,
    acme_auto_renew: false,
    created_at: '2026-01-01T00:00:00Z',
    source: 'manual',
    adcs_authority_id: null,
    adcs_template: null,
    adcs_template_oid: null,
    adcs_request_id: null,
    ...overrides,
  };
}

export function testCandidate(domain: string, overrides: Partial<AdcsAdoptionCandidate> = {}): AdcsAdoptionCandidate {
  return {
    certificate_id: `cert-${domain}`,
    domain,
    san_domains: [domain],
    subject: `CN=${domain},O=Example Corp,C=FR`,
    not_after: '2027-01-01T00:00:00Z',
    issued_template: '1.3.6.1.4.1.311.21.8.1.2',
    observed_template: '1.3.6.1.4.1.311.21.8.1.2',
    template_mismatch: false,
    ...overrides,
  };
}
