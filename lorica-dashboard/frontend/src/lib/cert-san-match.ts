/**
 * RFC 6125 hostname matching against a TLS certificate's SAN list:
 * its DNS names and, for a hostname that is an IP literal, its IP
 * addresses.
 *
 * Used by the route editor to flag a configured hostname that the
 * selected certificate does not cover, before the route goes live
 * and clients hit a real handshake error.
 *
 * The rules below mirror what mainstream browsers (Chrome, Firefox,
 * Safari) accept on the live handshake. Implementing the same rules
 * client-side means a "covered" verdict here predicts a successful
 * handshake, and an "uncovered" verdict predicts a real failure -
 * not a guess that may diverge from the browser.
 *
 * Matching rules:
 *   - DNS names are case-insensitive (RFC 5890); both sides are
 *     normalised to lowercase before comparison.
 *   - A trailing dot on either side is stripped (FQDN normalisation).
 *   - Exact match: SAN equals hostname after normalisation.
 *   - Wildcard match: SAN must start with "*." and the wildcard
 *     substitutes EXACTLY ONE label (no embedded dots). The wildcard
 *     must be the entire leftmost label - partial wildcards like
 *     "pki*.example.com" are rejected (Chrome and Firefox reject
 *     them; RFC 6125 6.4.3 considers them ambiguous).
 *   - "*.example.com" does NOT match "example.com" (the bare apex
 *     needs an explicit SAN entry).
 *   - SANs that are not pure wildcards or exact names (malformed
 *     inputs, multi-wildcard like "*.*.example.com") are ignored -
 *     they cannot match a hostname under the rules above.
 *
 * IP literals (issue #53):
 *   - Whether a hostname is an address is decided by `hostShape`, the
 *     dashboard's copy of `lorica_config::host_shape`: a name whose
 *     last label a browser reads as a number is an IPv4 address in
 *     some spelling, and only the dotted-decimal one is a route name a
 *     browser ever sends. `ip-literal.generated.ts` is the vector set
 *     both implementations replay.
 *   - An address hostname is matched against the certificate's IP
 *     address SANs only, by equality of canonical forms ("2001:DB8::1",
 *     "[2001:db8:0:0:0:0:0:1]" and "2001:db8::1" are one address). One
 *     spelled otherwise ("010.0.0.1") is covered by nothing: no request
 *     ever names it as written.
 *   - It never matches a DNS SAN, wildcard or not, even one spelling the
 *     same address: browsers verify an IP against IP address SANs alone.
 *   - An IPv4 hostname does not match an IPv4-mapped IPv6 SAN
 *     ("::ffff:192.0.2.10"), nor the reverse: the families differ.
 */

import type { HostKind } from './ip-literal.generated';

/** What a host name is to a browser's URL parser, and the address as a route stores it. */
export interface HostShape {
  readonly kind: HostKind;
  /** The address in the spelling a route stores it in, `null` when the name is no address. */
  readonly canonical: string | null;
}

const NOT_AN_ADDRESS: HostShape = { kind: 'not_an_address', canonical: null };

/** The URL Standard's IPv4 number parser, answering only whether it succeeds. */
function parsesAsAnIpv4Number(label: string): boolean {
  if (label === '') return false;
  if (/^0x/i.test(label)) return /^[0-9a-f]*$/i.test(label.slice(2));
  if (label.length >= 2 && label.startsWith('0')) return /^[0-7]*$/.test(label.slice(1));
  return /^[0-9]+$/.test(label);
}

/** The URL Standard's "ends in a number checker". */
function endsInANumber(name: string): boolean {
  const labels = name.split('.');
  let last = labels[labels.length - 1];
  if (last === '') {
    if (labels.length === 1) return false;
    last = labels[labels.length - 2];
  }
  return /^[0-9]+$/.test(last) || parsesAsAnIpv4Number(last);
}

/** Four decimal numbers from 0 to 255 without leading zeros. */
function isDottedQuad(name: string): boolean {
  const parts = name.split('.');
  return parts.length === 4 && parts.every((part) => /^(0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255);
}

/**
 * `text` as an IPv6 address, bracketed in the RFC 5952 spelling Rust's
 * `Ipv6Addr` displays (an IPv4-mapped address ends in dotted decimal),
 * or null. The browser's URL parser does the parsing.
 */
function ipv6Literal(text: string): string | null {
  if (!/^[0-9a-f:.]+$/i.test(text)) return null;
  let host: string;
  try {
    host = new URL(`http://[${text}]/`).hostname;
  } catch {
    return null;
  }
  const mapped = /^\[::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})\]$/.exec(host);
  if (mapped === null) return host;
  const high = parseInt(mapped[1], 16);
  const low = parseInt(mapped[2], 16);
  return `[::ffff:${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}]`;
}

/**
 * What `name` is to a browser's URL parser: the same rule as
 * `lorica_config::host_shape::host_shape`, held to it by the vectors of
 * `ip-literal.generated.ts`. One root dot is ignored; a bracketed name
 * is an IPv6 literal or nothing, an unbracketed one holding `:` an IPv6
 * address or nothing; otherwise a name ending in a number is an IPv4
 * address, canonical only as a dotted quad.
 */
export function hostShape(name: string): HostShape {
  const withoutRoot = name.endsWith('.') ? name.slice(0, -1) : name;
  if (withoutRoot.length >= 2 && withoutRoot.startsWith('[') && withoutRoot.endsWith(']')) {
    const literal = ipv6Literal(withoutRoot.slice(1, -1));
    return literal === null ? NOT_AN_ADDRESS : { kind: 'ipv6', canonical: literal };
  }
  if (withoutRoot.includes(':')) {
    const literal = ipv6Literal(withoutRoot);
    return literal === null ? NOT_AN_ADDRESS : { kind: 'ipv6', canonical: literal };
  }
  if (!endsInANumber(name)) return NOT_AN_ADDRESS;
  return isDottedQuad(withoutRoot)
    ? { kind: 'ipv4', canonical: withoutRoot }
    : { kind: 'non_canonical_ipv4', canonical: null };
}

/**
 * The canonical form of `host` when it is an IP address a browser sends
 * as written - IPv4 in dotted decimal, or IPv6 with or without brackets
 * - and null for anything else, another spelling of an IPv4 address
 * included.
 */
export function canonicalIp(host: string): string | null {
  return hostShape(host.trim()).canonical;
}

/** Whether `host` names an IP address in any spelling: never a DNS name. */
export function namesAnAddress(host: string): boolean {
  return hostShape(host.trim()).kind !== 'not_an_address';
}

/** A DNS name as both sides compare it: trimmed, lowercased, one root dot dropped. */
export function normalizeDnsName(name: string): string {
  let n = name.trim().toLowerCase();
  if (n.endsWith('.')) n = n.slice(0, -1);
  return n;
}

export function hostnameMatchesSan(hostname: string, san: string): boolean {
  const h = normalizeDnsName(hostname);
  const s = normalizeDnsName(san);
  if (h.length === 0 || s.length === 0) return false;

  if (s.startsWith('*.')) {
    // A wildcard never covers an address, whatever its tail spells.
    if (namesAnAddress(h)) return false;
    // Wildcard must be the entire leftmost label - reject partial
    // shapes like "*foo.example.com" or "foo*.example.com" (the
    // leading "*." check covers the leading variant; the included
    // remainder cannot itself contain "*").
    const remainder = s.slice(2);
    if (remainder.length === 0 || remainder.includes('*')) return false;

    const suffix = '.' + remainder;
    if (!h.endsWith(suffix)) return false;
    const prefix = h.slice(0, h.length - suffix.length);
    if (prefix.length === 0) return false;       // apex does not match
    if (prefix.includes('.')) return false;      // wildcard covers ONE label
    return true;
  }

  return h === s;
}

/**
 * Whether the certificate covers `hostname`: an address by `ipSans`
 * alone, any other hostname by the DNS names in `sans`. `ipSans` is
 * required, so a caller cannot leave a certificate's addresses out and
 * report an address it carries as uncovered.
 */
export function hostnameCoveredByAny(
  hostname: string,
  sans: readonly string[],
  ipSans: readonly string[],
): boolean {
  const shape = hostShape(hostname.trim());
  if (shape.kind === 'not_an_address') return sans.some((s) => hostnameMatchesSan(hostname, s));
  if (shape.canonical === null) return false;
  return ipSans.some((san) => canonicalIp(san) === shape.canonical);
}

/** The hostnames the certificate does not cover, in {@link hostnameCoveredByAny} terms. */
export function findUncoveredHostnames(
  hostnames: readonly string[],
  sans: readonly string[],
  ipSans: readonly string[],
): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of hostnames) {
    const h = raw.trim();
    if (h.length === 0) continue;
    const key = h.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    if (!hostnameCoveredByAny(h, sans, ipSans)) out.push(h);
  }
  return out;
}
