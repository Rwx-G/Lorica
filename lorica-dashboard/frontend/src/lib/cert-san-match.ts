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
 *   - A hostname that is an IPv4 literal, or an IPv6 literal with or
 *     without brackets, is matched against the certificate's IP
 *     address SANs only, by equality of canonical forms ("2001:DB8::1",
 *     "[2001:db8:0:0:0:0:0:1]" and "2001:db8::1" are one address).
 *   - It never matches a DNS SAN, not even one spelling the same
 *     address: browsers verify an IP against IP address SANs alone.
 *   - An IPv4 hostname does not match an IPv4-mapped IPv6 SAN
 *     ("::ffff:192.0.2.10"), nor the reverse: the families differ.
 */

/**
 * The canonical form of `host` when it is an IP literal - IPv4 in
 * dotted-decimal, or IPv6 with or without brackets - and null for
 * anything else. The browser's own URL parser canonicalises, so the
 * form is the one the browser compares.
 */
export function canonicalIp(host: string): string | null {
  let h = host.trim();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) {
    try {
      return new URL(`http://${h}/`).hostname;
    } catch {
      return null;
    }
  }
  if (h.includes(':')) {
    try {
      return new URL(`http://[${h}]/`).hostname;
    } catch {
      return null;
    }
  }
  return null;
}

function normalize(name: string): string {
  let n = name.trim().toLowerCase();
  if (n.endsWith('.')) n = n.slice(0, -1);
  return n;
}

export function hostnameMatchesSan(hostname: string, san: string): boolean {
  const h = normalize(hostname);
  const s = normalize(san);
  if (h.length === 0 || s.length === 0) return false;

  if (s.startsWith('*.')) {
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
 * Whether the certificate covers `hostname`: an IP literal by `ipSans`
 * alone, any other hostname by the DNS names in `sans`.
 */
export function hostnameCoveredByAny(
  hostname: string,
  sans: readonly string[],
  ipSans: readonly string[] = [],
): boolean {
  const ip = canonicalIp(hostname);
  if (ip !== null) return ipSans.some((san) => canonicalIp(san) === ip);
  return sans.some((s) => hostnameMatchesSan(hostname, s));
}

/** The hostnames the certificate does not cover, in {@link hostnameCoveredByAny} terms. */
export function findUncoveredHostnames(
  hostnames: readonly string[],
  sans: readonly string[],
  ipSans: readonly string[] = [],
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
