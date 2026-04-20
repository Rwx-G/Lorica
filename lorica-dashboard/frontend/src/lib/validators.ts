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

/**
 * Validate an HTTP field-name per RFC 7230 §3.2.6 (`token`). Mirrors
 * the server-side `validate_http_header_name` in lorica-api.
 */
export function validateHttpHeaderName(input: string): string | null {
  const s = input.trim();
  if (s.length === 0) return 'header name must not be empty';
  if (s.length > 256) return 'header name must be <= 256 characters';
  // RFC 7230 token: letters, digits, and !#$%&'*+-.^_`|~
  if (!/^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/.test(s)) {
    return 'header name contains a character that is not a valid HTTP field-name (RFC 7230 token)';
  }
  return null;
}

/**
 * Validate an HTTP field-value. Rejects CR, LF, and NUL (response
 * splitting) plus any value longer than 4096 chars. Mirrors
 * `validate_http_header_value` in lorica-api.
 */
export function validateHttpHeaderValue(input: string): string | null {
  if (input.length > 4096) return 'header value must be <= 4096 characters';
  if (/[\r\n\0]/.test(input)) return 'header value contains CR, LF, or NUL (response splitting)';
  return null;
}

/**
 * Validate an HTTP method token. Accepts any all-uppercase ASCII
 * letter sequence up to 32 chars (covers `GET`, `POST`, `PATCH`,
 * `MKCOL`, and operator-defined verbs). Mirrors
 * `validate_http_method` in lorica-api.
 */
export function validateHttpMethod(input: string): string | null {
  const s = input.trim();
  if (s.length === 0) return 'method must not be empty';
  if (s.length > 32) return 'method is longer than 32 characters';
  if (!/^[A-Z]+$/.test(s)) return 'method must be ASCII uppercase letters only (e.g. `GET`, `POST`)';
  return null;
}

/**
 * Validate a CORS origin entry. Accepts `*`, `null`, or a full
 * `scheme://host[:port]` URL without path/query/fragment. Mirrors
 * `validate_cors_origin` in lorica-api.
 */
export function validateCorsOrigin(input: string): string | null {
  const s = input.trim();
  if (s.length === 0) return null;
  if (s === '*' || s === 'null') return null;
  if (s.length > 2048) return 'origin is longer than 2048 characters';
  if (/\s/.test(s)) return 'origin contains whitespace';
  let rest: string;
  if (s.startsWith('http://')) rest = s.slice('http://'.length);
  else if (s.startsWith('https://')) rest = s.slice('https://'.length);
  else return 'origin must be `*`, `null`, or a `http(s)://host[:port]` URL';
  if (rest.length === 0) return 'origin must include a host after the scheme';
  if (/[/?#]/.test(rest)) return 'origin must not contain a path, query, or fragment';
  return null;
}

/**
 * Validate a comma-separated list of hostname aliases. Accepts bare
 * hostnames and leading-wildcard (`*.example.com`) entries. Mirrors
 * `validate_hostname_alias` in lorica-api.
 */
export function validateHostnameAliasList(input: string): string | null {
  const raw = input.trim();
  if (raw === '') return null;
  const entries = raw.split(/[,\n]/).map((s) => s.trim()).filter((s) => s.length > 0);
  for (let i = 0; i < entries.length; i++) {
    const err = validateHostnameAlias(entries[i]);
    if (err) return `alias #${i + 1} (${entries[i]}): ${err}`;
  }
  return null;
}

function validateHostnameAlias(value: string): string | null {
  if (value.length > 253) return 'longer than 253 characters';
  if (value.includes('://') || value.includes('/')) return 'must be a bare hostname';
  if (/\s/.test(value)) return 'contains whitespace';
  if (value.startsWith('.') || value.endsWith('.')) return 'starts or ends with a dot';
  const body = value.startsWith('*.') ? value.slice(2) : value;
  for (const label of body.split('.')) {
    if (label === '') return 'empty DNS label';
    if (label.length > 63) return 'DNS label longer than 63 chars';
    if (label.startsWith('-') || label.endsWith('-')) return 'DNS label starts/ends with `-`';
    if (!/^[A-Za-z0-9-]+$/.test(label)) return 'non-ASCII or invalid character in label';
  }
  return null;
}

/**
 * Validate an `error_page_html` body. Only a size cap: the runtime
 * sanitiser strips dangerous elements so we don't try to emulate it
 * on the client.
 */
export function validateErrorPageHtml(input: string): string | null {
  if (input.length > 128 * 1024) return 'HTML must be <= 128 KiB';
  return null;
}

/**
 * Validate a `group_name` for a Route or a Backend. Empty string
 * (after trim) is accepted as "ungrouped". Non-empty must match the
 * RFC-1035-inspired identifier alphabet `^[a-z0-9_-]{1,64}$`:
 * lowercase ASCII letters, digits, dash and underscore. Mirrors the
 * server-side `validate_group_name` in lorica-api so the UI can fail
 * fast with the same contract.
 */
export function validateGroupName(input: string): string | null {
  const s = input.trim();
  if (s === '') return null;
  if (s.length > 64) return 'group name must be <= 64 characters';
  if (!/^[a-z0-9_-]+$/.test(s)) {
    return 'group name may only contain ASCII lowercase letters, digits, `-` and `_`';
  }
  return null;
}

/**
 * Validate a path-prefix-style field (route `path_prefix`,
 * `strip_path_prefix`, `add_path_prefix`, path-rule paths). Empty
 * => null ("clear the field"). Non-empty value must start with
 * `/`, have no whitespace or control characters, and fit in 1024
 * chars. Mirrors `validate_route_path` in lorica-api.
 */
export function validateRoutePath(input: string): string | null {
  const s = input.trim();
  if (s === '') return null;
  if (!s.startsWith('/')) return "must start with '/'";
  if (s.length > 1024) return 'must be <= 1024 characters';
  if (/\s/.test(s)) return 'must not contain whitespace';
  for (const c of s) {
    const code = c.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return 'contains a control character';
  }
  return null;
}

/**
 * Validate a single mTLS "allowed organization" string.
 */
export function validateMtlsOrganization(input: string): string | null {
  const s = input.trim();
  if (s.length === 0) return 'must not be empty';
  if (s.length > 256) return 'longer than 256 characters';
  for (const c of s) {
    const code = c.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return 'contains a control character';
  }
  return null;
}

/**
 * Validate the comma-or-newline separated textarea `mtls_allowed_organizations`.
 * Caps the entry count at 100, matches `build_mtls_config` in lorica-api.
 */
export function validateMtlsOrganizationList(input: string): string | null {
  const raw = input.trim();
  if (raw === '') return null;
  const parts = raw.split(/[,\n]/).map((s) => s.trim()).filter((s) => s.length > 0);
  if (parts.length > 100) return 'at most 100 organizations allowed';
  const seen = new Set<string>();
  for (let i = 0; i < parts.length; i++) {
    const err = validateMtlsOrganization(parts[i]);
    if (err) return `organization #${i + 1}: ${err}`;
    seen.add(parts[i]);
  }
  return null;
}

/**
 * Validate a PEM bundle for the `mtls_ca_cert_pem` field. The
 * authoritative check runs server-side (`build_mtls_config` parses
 * the PEM and each CERTIFICATE block as DER); this shape check
 * catches the common mistakes before the operator clicks Save:
 * missing markers, missing END, empty body, or a bundle larger
 * than the 1 MiB server-side cap.
 */
export function validateMtlsPemShape(input: string): string | null {
  const pem = input.trim();
  if (pem === '') return null;
  if (pem.length > 1_048_576) return 'bundle is larger than 1 MiB; trim to issuing CAs only';
  const begin = /-----BEGIN CERTIFICATE-----/.test(pem);
  const end = /-----END CERTIFICATE-----/.test(pem);
  if (!begin) return 'must contain at least one `-----BEGIN CERTIFICATE-----` block';
  if (!end) return 'missing `-----END CERTIFICATE-----` marker';
  return null;
}

/**
 * Validate a `key=value\nkey=value` textarea the dashboard uses for
 * `proxy_headers` / `response_headers`. Returns the first error
 * encountered (with a 1-based line number for diagnostics) or `null`
 * if every line parses as a valid HTTP header name + value pair.
 */
export function validateHeadersMapText(input: string): string | null {
  const lines = input.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (trimmed === '') continue;
    const idx = trimmed.indexOf('=');
    if (idx <= 0) {
      return `line ${i + 1}: expected \`key=value\``;
    }
    const name = trimmed.slice(0, idx).trim();
    const value = trimmed.slice(idx + 1).trim();
    const nameErr = validateHttpHeaderName(name);
    if (nameErr) return `line ${i + 1}: ${nameErr}`;
    const valueErr = validateHttpHeaderValue(value);
    if (valueErr) return `line ${i + 1}: ${valueErr}`;
  }
  return null;
}

/**
 * Validate a comma-separated list of HTTP header names. Used for
 * `proxy_headers_remove` / `response_headers_remove` /
 * `cache_vary_headers`.
 */
export function validateHttpHeaderNameList(input: string): string | null {
  const s = input.trim();
  if (s.length === 0) return null;
  const entries = s.split(',').map((e) => e.trim()).filter((e) => e.length > 0);
  for (const name of entries) {
    const err = validateHttpHeaderName(name);
    if (err) return `${name}: ${err}`;
  }
  return null;
}

/**
 * Validate a comma-separated list of HTTP methods. Used for
 * `cors_allowed_methods` and `retry_on_methods`.
 */
export function validateHttpMethodList(input: string): string | null {
  const s = input.trim();
  if (s.length === 0) return null;
  const entries = s.split(',').map((e) => e.trim()).filter((e) => e.length > 0);
  for (const method of entries) {
    const err = validateHttpMethod(method);
    if (err) return `${method}: ${err}`;
  }
  return null;
}

/**
 * Validate a comma-separated list of CORS origins.
 */
export function validateCorsOriginList(input: string): string | null {
  const s = input.trim();
  if (s.length === 0) return null;
  const entries = s.split(',').map((e) => e.trim()).filter((e) => e.length > 0);
  for (const origin of entries) {
    const err = validateCorsOrigin(origin);
    if (err) return `${origin}: ${err}`;
  }
  return null;
}

/**
 * Validate a regex replacement string against its pattern. When the
 * pattern is non-empty, rejects `$N` references to capture groups
 * that don't exist in the pattern (e.g. `$1` against `/foo` would
 * render as a literal `$1` in the rewritten output - a correctness
 * footgun the operator can't diagnose from the proxy log). `$$` in
 * the replacement is treated as a literal `$` and skipped. Mirrors
 * the server-side `validate_path_rewrite_replacement` +
 * `build_response_rewrite` logic so the UI can fail fast with the
 * same contract.
 */
export function validateRewriteReplacement(replacement: string, pattern: string): string | null {
  if (replacement.length > 2048) return 'replacement longer than 2048 characters';
  const p = pattern.trim();
  if (p === '') return null;
  let groupCount = 0;
  try {
    // Compile check mirrors validateRegex; we swallow failures here
    // because the pattern-level validator will surface them.
    new RegExp(p);
    // Walk the pattern to count capturing groups. JavaScript does not
    // expose `RegExp.prototype.captureLength`, so we replicate the
    // rule the regex crate uses: `(` opens a group unless it is
    // preceded by `\` or introduces a non-capturing construct
    // (`(?:`, `(?=`, `(?!`) or a lookbehind without a name
    // (`(?<=`, `(?<!`). Named groups (`(?<name>...)`) count.
    let i = 0;
    while (i < p.length) {
      if (p[i] === '\\') { i += 2; continue; }
      if (p[i] === '(') {
        if (p[i + 1] === '?') {
          if (p[i + 2] === ':' || p[i + 2] === '=' || p[i + 2] === '!') { i++; continue; }
          if (p[i + 2] === '<' && (p[i + 3] === '=' || p[i + 3] === '!')) { i++; continue; }
        }
        groupCount++;
      }
      i++;
    }
  } catch {
    return null;
  }
  const scan = replacement.replace(/\$\$/g, '');
  const refRe = /\$(\d+)/g;
  let m: RegExpExecArray | null;
  while ((m = refRe.exec(scan)) !== null) {
    const n = Number(m[1]);
    if (n > groupCount) {
      return `replacement references \`$${n}\` but the pattern has only ${groupCount} capture group${groupCount === 1 ? '' : 's'}`;
    }
  }
  return null;
}
