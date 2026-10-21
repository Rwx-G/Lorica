/**
 * Shared AD CS fixtures for the Vitest suites of Story 13.3. A plain
 * module rather than an export of a test file, which would register
 * that file's suites a second time in every importer.
 */
import type { AdcsAuthority, AdcsAuthorityState, CertificateResponse } from './lib/api';

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

export function testAuthorityState(overrides: Partial<AdcsAuthorityState> = {}): AdcsAuthorityState {
  return { authority: testAuthority(), managed_on_control_plane: false, ...overrides };
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
