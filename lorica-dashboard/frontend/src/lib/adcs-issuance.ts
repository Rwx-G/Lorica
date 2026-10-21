/**
 * Pure helpers behind AD CS issuance in the dashboard (Story 13.3):
 * the names a route still needs a certificate for, the advisory SAN
 * hints, the request summary the operator confirms, when issuance is
 * offered at all, and how an answer reads. Renewal (Story 13.4) is an
 * issuance at the authority, so it shares the same rules.
 *
 * Everything here is advisory. The API checks the allowlist, refuses
 * wildcards and every other condition itself, and its messages are
 * shown verbatim.
 */

import type {
  AcmeRenewResult,
  AdcsAuthority,
  AdcsAuthorityState,
  AdcsIssuePending,
  AdcsIssueRequest,
  AdcsIssueResult,
  AdcsKeyType,
  AdcsSubjectDefaults,
  AdcsSubjectOverrides,
  ApiError,
  ApiResponse,
  CertificateDownloadPart,
  CertificateRenewResult,
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

export const ADCS_RENEWAL_STILL_FINISHING =
  'The renewal is still finishing on the server. Reload the certificate list before retrying shortly: it may have completed.';

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
 *
 * Deliberately coarse: it only drives a hint. `AllowedSuffix::permits`
 * in `lorica-config` is the rule the API applies, and a name the two
 * read differently is refused by the API with its own message.
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
 * The templates an issuance may request (Epic 13 D17): the default
 * first, then the others, each name once. The API compares template
 * names without regard to ASCII case, so the list does too.
 */
export function adcsTemplateOptions(
  authority: Pick<AdcsAuthority, 'default_template' | 'allowed_templates'>,
): string[] {
  const out: string[] = [];
  for (const name of [authority.default_template, ...authority.allowed_templates]) {
    if (!out.some((kept) => kept.toLowerCase() === name.toLowerCase())) out.push(name);
  }
  return out;
}

/**
 * Whether this node is a follower for AD CS: the cluster role says so
 * before the authority read lands, the API's `managed_on_control_plane`
 * after. A follower refuses every AD CS operation, break-glass window
 * or not, so the role-based write gates (which reopen during
 * break-glass) are not enough on their own.
 */
export function isAdcsFollower(
  role: string | null,
  state: Pick<AdcsAuthorityState, 'managed_on_control_plane'> | null,
): boolean {
  return role === 'follower' || Boolean(state?.managed_on_control_plane);
}

/**
 * Why issuance is not offered, or `null` when it is. `follower` is the
 * cluster role; the API's `managed_on_control_plane` is read from
 * `state`. Configured and failed come from the summary every role
 * reads (D18), so the answer never depends on the connection details.
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
  const summary = input.state?.summary ?? null;
  if (!input.state?.configured || summary === null) {
    return 'No AD CS authority is configured. A SuperAdmin configures it under Settings.';
  }
  if (summary.failed_since) {
    return 'The AD CS authority is in the failed state: its credential was rejected, and every AD CS operation is suspended until a SuperAdmin saves a new password under Settings.';
  }
  return null;
}

/**
 * Whether "Renew now" is offered on an AD CS certificate: a renewal is
 * an issuance at the authority, refused by the API under exactly the
 * same conditions.
 */
export function adcsRenewalOffered(input: Parameters<typeof adcsIssuanceBlocker>[0]): boolean {
  return adcsIssuanceBlocker(input) === null;
}

/** The API's message, plus the failing step of an `adcs_error` when the message does not name it. */
export function adcsErrorMessage(error: ApiError): string {
  if (error.step && !error.message.includes(error.step)) {
    return `${error.message} (failing step: ${error.step})`;
  }
  return error.message;
}

/** An answer that stored nothing: pending at the authority, or refused. */
export type AdcsUnsettledOutcome =
  | { kind: 'pending'; requestId: string; message: string }
  | { kind: 'refused'; message: string };

export type AdcsIssueOutcome = { kind: 'issued'; certificate: CertificateResponse } | AdcsUnsettledOutcome;

/**
 * `certificate` is null only if the server answered the ACME shape,
 * which carries no certificate to show.
 */
export type AdcsRenewOutcome =
  | { kind: 'renewed'; certificate: CertificateResponse | null }
  | AdcsUnsettledOutcome;

/**
 * The reading issuance and renewal share: a refusal or a 202 pending
 * body, or the success body for the caller to read.
 */
function readAdcsAnswer<T extends object>(
  res: ApiResponse<T | AdcsIssuePending>,
  stillFinishing: string,
): AdcsUnsettledOutcome | { kind: 'success'; data: T } {
  if (res.error) {
    // A 504 can come from a reverse proxy with no envelope, so the
    // status alone decides, whatever the body says.
    if (res.error.status === 504) return { kind: 'refused', message: stillFinishing };
    return { kind: 'refused', message: adcsErrorMessage(res.error) };
  }
  const data = res.data;
  if (!data) return { kind: 'refused', message: 'The server returned an empty answer.' };
  if ('outcome' in data) return { kind: 'pending', requestId: data.request_id, message: data.message };
  return { kind: 'success', data };
}

export function adcsIssueOutcome(res: ApiResponse<AdcsIssueResult>): AdcsIssueOutcome {
  const read = readAdcsAnswer<CertificateResponse>(res, ADCS_STILL_FINISHING);
  return read.kind === 'success' ? { kind: 'issued', certificate: read.data } : read;
}

export function adcsRenewOutcome(res: ApiResponse<CertificateRenewResult>): AdcsRenewOutcome {
  const read = readAdcsAnswer<AcmeRenewResult | CertificateResponse>(res, ADCS_RENEWAL_STILL_FINISHING);
  if (read.kind !== 'success') return read;
  return { kind: 'renewed', certificate: 'renewed' in read.data ? null : read.data };
}

export const ADCS_KEY_NOT_EXPORTABLE_HINT =
  'The private key of an AD CS certificate never leaves Lorica, so neither the key nor the bundle can be downloaded. The certificate and its chain can.';

/**
 * Why a part of this certificate is not offered for download, or `null`
 * when it is: the key of an AD CS certificate never leaves Lorica
 * (Epic 13 D16), and the API refuses it for every role with 403
 * `adcs_key_not_exportable`.
 */
export function downloadPartRefusal(
  cert: Pick<CertificateResponse, 'source'>,
  part: CertificateDownloadPart,
): string | null {
  if (cert.source === 'adcs' && (part === 'key' || part === 'bundle')) return ADCS_KEY_NOT_EXPORTABLE_HINT;
  return null;
}

/**
 * Why the domain, certificate and key of this certificate cannot be
 * replaced, or `null` when they can: the authority issues and renews
 * an AD CS certificate, and the API refuses a replacement with 409
 * `adcs_certificate_managed`. Auto-renew stays editable.
 */
export function adcsManagedCertificateNotice(cert: Pick<CertificateResponse, 'source'>): string | null {
  if (cert.source !== 'adcs') return null;
  return 'The AD CS authority issues and renews this certificate, so its domain, certificate and key cannot be replaced here. Revert it to manual first to replace them. Auto-renew stays editable.';
}
