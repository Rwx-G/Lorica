/**
 * Pure helpers behind AD CS issuance in the dashboard (Story 13.3):
 * the names a route still needs a certificate for, the advisory SAN
 * hints, the request summary the operator confirms, when issuance is
 * offered at all, and how an answer reads.
 *
 * Everything here is advisory. The API checks the allowlist, refuses
 * wildcards and every other condition itself, and its messages are
 * shown verbatim.
 */

import type {
  AdcsAuthority,
  AdcsAuthorityState,
  AdcsIssueRequest,
  AdcsIssueResult,
  AdcsKeyType,
  AdcsSubjectDefaults,
  AdcsSubjectOverrides,
  ApiResponse,
  CertificateResponse,
} from './api';
import { findUncoveredHostnames } from './cert-san-match';

// A Record rather than a list, so the compiler refuses a key type
// added to `AdcsKeyType` without a label here.
export const ADCS_KEY_TYPE_LABELS: Record<AdcsKeyType, string> = {
  rsa2048: 'RSA 2048',
  rsa3072: 'RSA 3072',
  ecdsa_p256: 'ECDSA P-256',
};
export const ADCS_KEY_TYPES = Object.keys(ADCS_KEY_TYPE_LABELS) as AdcsKeyType[];

// Same reason: a subject field added to the authority must get a label.
export const ADCS_SUBJECT_LABELS: Record<keyof AdcsSubjectDefaults, string> = {
  country: 'Country (C)',
  state: 'State or province (ST)',
  locality: 'Locality (L)',
  organization: 'Organization (O)',
  organizational_unit: 'Organizational unit (OU)',
  email: 'Email',
};
export const ADCS_SUBJECT_FIELDS = Object.keys(ADCS_SUBJECT_LABELS) as (keyof AdcsSubjectDefaults)[];

export const ADCS_STILL_FINISHING =
  'The issuance is still finishing on the server. Check the certificate list before retrying shortly: it may have completed.';

function normalize(name: string): string {
  let n = name.trim().toLowerCase();
  if (n.endsWith('.')) n = n.slice(0, -1);
  return n;
}

export function isWildcardName(name: string): boolean {
  return name.includes('*');
}

/** One name per line or comma, trimmed, empty entries and case-insensitive duplicates dropped. */
export function parseSanList(text: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of text.split(/[,\n]/)) {
    const name = raw.trim();
    if (name.length === 0) continue;
    const key = normalize(name);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(name);
  }
  return out;
}

/**
 * Whether `name` is `suffix` or under it, compared label by label
 * (Epic 13 D5): `corp.example.org` permits `www.corp.example.org` and
 * never `evilcorp.example.org`.
 */
export function nameUnderSuffix(name: string, suffix: string): boolean {
  const n = normalize(name);
  const s = normalize(suffix);
  if (n.length === 0 || s.length === 0) return false;
  return n === s || n.endsWith('.' + s);
}

export interface SanHints {
  wildcards: string[];
  outsideSuffixes: string[];
}

export function adcsSanHints(sans: readonly string[], allowedSuffixes: readonly string[]): SanHints {
  const wildcards = sans.filter(isWildcardName);
  const outsideSuffixes = sans.filter(
    (name) => !isWildcardName(name) && !allowedSuffixes.some((suffix) => nameUnderSuffix(name, suffix)),
  );
  return { wildcards, outsideSuffixes };
}

/**
 * The route's names that no stored certificate covers, by its `domain`
 * or any SAN, in RFC 6125 terms. Wildcard names are dropped first:
 * AD CS issuance refuses them (Epic 13 D5), so offering them would
 * only produce a refusal.
 */
export function hostnamesWithoutCertificate(
  hostnames: readonly string[],
  certificates: readonly CertificateResponse[],
): string[] {
  const names = certificates.flatMap((cert) => [cert.domain, ...cert.san_domains]);
  return findUncoveredHostnames(
    hostnames.filter((name) => !isWildcardName(name)),
    names,
  );
}

/** Only the fields the operator changed from the authority's defaults, and never a blank one. */
export function subjectOverrides(
  defaults: AdcsSubjectDefaults,
  edited: Record<keyof AdcsSubjectDefaults, string>,
): AdcsSubjectOverrides | undefined {
  const out: AdcsSubjectOverrides = {};
  for (const field of ADCS_SUBJECT_FIELDS) {
    const value = edited[field].trim();
    if (value !== '' && value !== (defaults[field] ?? '')) out[field] = value;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

export interface SubjectLine {
  label: string;
  value: string;
}

export interface AdcsRequestSummary {
  template: string;
  keyType: string;
  subject: SubjectLine[];
  sans: string[];
  autoRenew: boolean;
}

/**
 * The full request as the API will assemble it: the authority's
 * defaults with the request's overrides on top, and `CN` the first
 * SAN.
 */
export function adcsRequestSummary(authority: AdcsAuthority, request: AdcsIssueRequest): AdcsRequestSummary {
  const subject: SubjectLine[] = [];
  if (request.sans.length > 0) subject.push({ label: 'Common name (CN)', value: request.sans[0] });
  for (const field of ADCS_SUBJECT_FIELDS) {
    const value = request.subject?.[field]?.trim() || authority.subject[field];
    if (value) subject.push({ label: ADCS_SUBJECT_LABELS[field], value });
  }
  return {
    template: request.template ?? authority.default_template,
    keyType: ADCS_KEY_TYPE_LABELS[request.key_type ?? authority.default_key_type],
    subject,
    sans: request.sans,
    autoRenew: request.auto_renew ?? authority.auto_renew_default,
  };
}

/**
 * Why issuance is not offered, or `null` when it is. `follower` is the
 * API's `managed_on_control_plane` or the cluster role: a follower
 * refuses every AD CS operation, break-glass window or not.
 */
export function adcsIssuanceBlocker(input: {
  canIssue: boolean;
  follower: boolean;
  state: AdcsAuthorityState | null;
}): string | null {
  if (!input.canIssue) return 'Issuing a certificate from the AD CS authority needs the Operator role.';
  if (input.follower || input.state?.managed_on_control_plane) {
    return 'AD CS issuance runs on the control plane. This node is a follower: open the dashboard of the control plane to issue a certificate.';
  }
  const authority = input.state?.authority ?? null;
  if (authority === null) {
    return 'No AD CS authority is configured. A SuperAdmin configures it under Settings.';
  }
  if (authority.failed_since) {
    return 'The AD CS authority is in the failed state: its credential was rejected, and every AD CS operation is suspended until a SuperAdmin saves a new password under Settings.';
  }
  return null;
}

export type AdcsIssueOutcome =
  | { kind: 'issued'; certificate: CertificateResponse }
  | { kind: 'pending'; requestId: string; message: string }
  | { kind: 'refused'; message: string };

export function adcsIssueOutcome(res: ApiResponse<AdcsIssueResult>): AdcsIssueOutcome {
  if (res.error) {
    // A 504 can come from a reverse proxy with no envelope, so the
    // status alone decides, whatever the body says.
    if (res.error.status === 504) return { kind: 'refused', message: ADCS_STILL_FINISHING };
    return { kind: 'refused', message: res.error.message };
  }
  const data = res.data;
  if (data && 'outcome' in data) {
    return { kind: 'pending', requestId: data.request_id, message: data.message };
  }
  if (data) return { kind: 'issued', certificate: data };
  return { kind: 'refused', message: 'The server returned an empty answer.' };
}
