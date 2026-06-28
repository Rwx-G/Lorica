import type {
  AiCrawlerVerification,
  AiCrawlerVerificationKind,
  CustomCrawler,
  CustomCrawlerBody,
} from './api';

/**
 * Editor state for the custom-crawler form. The verification union is
 * flattened into a `kind` selector plus two textareas (one for rDNS
 * suffixes, one for IP-range CIDRs) so the operator only ever sees the
 * fields relevant to the selected kind. `buildVerification` folds these
 * back into the discriminated union the API expects.
 */
export interface CrawlerEditState {
  name: string;
  user_agent_pattern: string;
  kind: AiCrawlerVerificationKind;
  suffixes: string;
  cidrs: string;
  enabled: boolean;
}

/** Split a comma/newline-separated list, trim, drop empty entries. */
function tokenList(text: string): string[] {
  return text
    .split(/[,\n]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export function emptyCrawlerEdit(): CrawlerEditState {
  return {
    name: '',
    user_agent_pattern: '',
    kind: 'ua_only',
    suffixes: '',
    cidrs: '',
    enabled: true,
  };
}

export function crawlerToEdit(c: CustomCrawler): CrawlerEditState {
  const base: CrawlerEditState = {
    name: c.name,
    user_agent_pattern: c.user_agent_pattern,
    kind: c.verification.kind,
    suffixes: '',
    cidrs: '',
    enabled: c.enabled,
  };
  if (c.verification.kind === 'rdns') {
    base.suffixes = c.verification.suffixes.join('\n');
  } else if (c.verification.kind === 'ip_ranges') {
    base.cidrs = c.verification.cidrs.join('\n');
  }
  return base;
}

/**
 * Shape the editor's flat fields into the `verification` discriminated
 * union. Only the textarea matching the selected `kind` is read; the
 * other is ignored, so switching kinds never leaks stale entries into
 * the payload.
 */
export function buildVerification(state: CrawlerEditState): AiCrawlerVerification {
  switch (state.kind) {
    case 'rdns':
      return { kind: 'rdns', suffixes: tokenList(state.suffixes) };
    case 'ip_ranges':
      return { kind: 'ip_ranges', cidrs: tokenList(state.cidrs) };
    case 'ua_only':
      return { kind: 'ua_only' };
  }
}

export function editToBody(state: CrawlerEditState): CustomCrawlerBody {
  return {
    name: state.name.trim(),
    user_agent_pattern: state.user_agent_pattern.trim(),
    verification: buildVerification(state),
    enabled: state.enabled,
  };
}

export function verificationKindLabel(kind: AiCrawlerVerificationKind): string {
  switch (kind) {
    case 'rdns':
      return 'rDNS';
    case 'ip_ranges':
      return 'IP ranges';
    case 'ua_only':
      return 'UA only';
  }
}

export function verificationKindTooltip(kind: AiCrawlerVerificationKind): string {
  switch (kind) {
    case 'rdns':
      return 'Forward-confirmed reverse DNS: the client PTR record must end with one of the configured suffixes and resolve back to the same IP.';
    case 'ip_ranges':
      return 'The client IP must fall inside one of the published CIDR ranges for this crawler.';
    case 'ua_only':
      return 'User-Agent string match only, with no network verification. Trivially spoofable, so treat matches with caution.';
  }
}

export function verificationSummary(v: AiCrawlerVerification): string {
  switch (v.kind) {
    case 'rdns':
      return `rDNS (${v.suffixes.length} suffix${v.suffixes.length === 1 ? '' : 'es'})`;
    case 'ip_ranges':
      return `IP ranges (${v.cidrs.length} CIDR${v.cidrs.length === 1 ? '' : 's'})`;
    case 'ua_only':
      return 'UA only';
  }
}
