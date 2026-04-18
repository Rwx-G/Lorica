/**
 * Field-level validators shared by the Edit Route drawer. Each
 * validator returns `null` on success or a short human-readable
 * error message on failure. They are intentionally tolerant - the
 * API-layer validator in Rust is the source of truth; these
 * frontend checks just catch obvious typos at blur time so the
 * operator does not click Save and get an auto-tab-switch error.
 *
 * Resolves UXUI.md findings #7 (validation au blur) + powers the
 * per-chip validation inside `ChipListInput` (#8).
 */

/**
 * Validate a CIDR block or bare IPv4/IPv6 address. Accepts:
 *   192.168.1.0/24, 10.0.0.1, 2001:db8::/32, ::1
 * Does not normalise - just checks the shape.
 */
export function validateCidr(input: string): string | null {
  const s = input.trim();
  if (s.length === 0) return null;
  const slash = s.indexOf('/');
  const addr = slash === -1 ? s : s.slice(0, slash);
  const prefix = slash === -1 ? null : s.slice(slash + 1);
  if (prefix !== null) {
    if (!/^\d+$/.test(prefix)) return 'prefix length must be numeric';
    const n = Number(prefix);
    if (n < 0) return 'prefix length must be >= 0';
  }
  if (addr.includes(':')) {
    // IPv6: allow "::" shorthand, hex groups, optional zone id (%eth0)
    if (prefix !== null && Number(prefix) > 128) return 'IPv6 prefix must be <= 128';
    const addrNoZone = addr.split('%')[0];
    if (!/^[0-9a-fA-F:]+$/.test(addrNoZone)) return 'not a valid IPv6 address';
    // Very rough shape check: one "::" allowed, groups at most 8
    const parts = addrNoZone.split(':');
    if (parts.length < 3 || parts.length > 8) return 'not a valid IPv6 address';
    return null;
  }
  // IPv4
  if (prefix !== null && Number(prefix) > 32) return 'IPv4 prefix must be <= 32';
  const octets = addr.split('.');
  if (octets.length !== 4) return 'not a valid IPv4 address';
  for (const octet of octets) {
    if (!/^\d+$/.test(octet)) return 'not a valid IPv4 address';
    const v = Number(octet);
    if (v < 0 || v > 255) return 'IPv4 octet out of range (0-255)';
  }
  return null;
}

/**
 * Validate a regex pattern by compiling it. Catches operator typos
 * (unterminated groups, bad escapes, lookahead where unsupported).
 * Uses the JS engine which is close enough to Rust's `regex` crate
 * for the typos that matter at this layer; a pattern accepted here
 * that fails server-side still falls back to the API error path.
 */
export function validateRegex(input: string): string | null {
  const s = input.trim();
  if (s.length === 0) return null;
  try {
    new RegExp(s);
    return null;
  } catch (e) {
    return e instanceof Error ? e.message.replace(/^Invalid regular expression:\s*/, '') : 'invalid regex';
  }
}

/**
 * Validate an http(s) URL. Rejects anything without a scheme + host
 * (the API validator in Rust requires those too).
 */
export function validateUrl(input: string): string | null {
  const s = input.trim();
  if (s.length === 0) return null;
  if (!/^https?:\/\//i.test(s)) return 'must start with http:// or https://';
  try {
    const u = new URL(s);
    if (!u.hostname) return 'missing hostname';
    return null;
  } catch {
    return 'not a valid URL';
  }
}

/**
 * Validate an ASN. Accepts "AS15169" or "15169". 0 is reserved.
 */
export function validateAsn(input: string): string | null {
  const s = input.trim().replace(/^AS/i, '');
  if (s.length === 0) return null;
  if (!/^\d+$/.test(s)) return 'must be an integer ASN (optional AS prefix)';
  const n = Number(s);
  if (n <= 0) return 'ASN must be > 0 (AS0 is IANA-reserved)';
  if (n > 4294967295) return 'ASN must fit in a 32-bit unsigned integer';
  return null;
}

/**
 * Validate a DNS suffix used for rDNS bypass. Rejects bare TLDs,
 * leading dots, and non-printable characters.
 */
export function validateDnsSuffix(input: string): string | null {
  const s = input.trim();
  if (s.length === 0) return null;
  if (s.startsWith('.')) return 'must not start with a dot';
  if (!s.includes('.')) return 'bare TLD rejected; use e.g. googlebot.com';
  if (!/^[a-zA-Z0-9.-]+$/.test(s)) return 'only letters, digits, dashes and dots allowed';
  return null;
}

/**
 * Validate an ISO 3166-1 alpha-2 country code. Two letters,
 * case-insensitive (the API validator normalises to uppercase).
 */
export function validateIso3166Alpha2(input: string): string | null {
  const s = input.trim();
  if (s.length === 0) return null;
  if (!/^[a-zA-Z]{2}$/.test(s)) return 'must be a 2-letter ISO 3166-1 code (e.g. FR, DE)';
  return null;
}
