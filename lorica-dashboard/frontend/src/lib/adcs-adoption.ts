/**
 * Pure helpers behind AD CS adoption in the dashboard (Story 13.5):
 * what the certificate page announces, how a candidate's template
 * reads, and the per-certificate sequence a bulk adoption runs.
 *
 * Candidacy is the API's decision, re-checked on every adoption; the
 * dashboard only shows what it was told and the answers it gets.
 */

import type {
  AdcsAdoptionCandidate,
  AdcsAdoptionCandidates,
  ApiResponse,
  CertificateResponse,
} from './api';
import { adcsErrorMessage } from './adcs-issuance';

export const ADCS_NO_ISSUING_CA_HINT =
  'Certificates issued by hand before Lorica cannot be offered for adoption yet: the AD CS authority does not know its issuing CA certificate. Issue one certificate through Lorica, or paste the issuing CA certificate in the AD CS authority settings.';

export const ADCS_TEMPLATE_UNKNOWN = 'unknown';

export type AdcsAdoptionBanner =
  | { kind: 'candidates'; count: number }
  | { kind: 'no_issuing_ca' }
  | null;

/**
 * What the certificate page announces about adoption, or `null`.
 * Adoption is an Operator action refused on a follower (even in a
 * break-glass window), so nobody else is told about it. With no
 * authority configured there is nothing to adopt into, and nothing to
 * say.
 */
export function adcsAdoptionBanner(input: {
  canAdopt: boolean;
  follower: boolean;
  candidates: AdcsAdoptionCandidates | null;
}): AdcsAdoptionBanner {
  if (!input.canAdopt || input.follower || input.candidates === null) return null;
  if (input.candidates.reason === 'no_issuing_ca') return { kind: 'no_issuing_ca' };
  if (input.candidates.reason !== null) return null;
  const count = input.candidates.candidates.length;
  return count > 0 ? { kind: 'candidates', count } : null;
}

export function adcsTemplateLabel(template: string | null): string {
  return template ?? ADCS_TEMPLATE_UNKNOWN;
}

export interface AdcsAdoptionResult {
  certificateId: string;
  domain: string;
  ok: boolean;
  message: string;
}

/**
 * Adopt each candidate in turn, never two at once: every call is a
 * write the API audits and re-checks, and a failure on one must not
 * stop the others. `autoRenewFor` gives the choice made for each.
 */
export async function adoptInSequence(
  candidates: readonly AdcsAdoptionCandidate[],
  autoRenewFor: (candidate: AdcsAdoptionCandidate) => boolean,
  adopt: (id: string, body: { auto_renew: boolean }) => Promise<ApiResponse<CertificateResponse>>,
): Promise<AdcsAdoptionResult[]> {
  const results: AdcsAdoptionResult[] = [];
  for (const candidate of candidates) {
    const res = await adopt(candidate.certificate_id, { auto_renew: autoRenewFor(candidate) });
    results.push({
      certificateId: candidate.certificate_id,
      domain: candidate.domain,
      ok: !res.error,
      message: res.error ? adcsErrorMessage(res.error) : 'Adopted: now managed by the AD CS authority.',
    });
  }
  return results;
}
