/**
 * Standalone Nginx configuration parser for Lorica dashboard.
 *
 * Provides line-based parsing of Nginx config text and conversion
 * to Lorica route import structures. No UI dependencies - pure functions only.
 *
 * @module nginx-parser
 * @author Romain G.
 * @license Apache-2.0
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A single Nginx directive with its name, value, and source line number. */
export interface NginxDirective {
  name: string;
  value: string;
  line: number;
}

/** A parsed `location` block within a server block. */
export interface NginxLocation {
  path: string;
  proxyPass: string | null;
  directives: NginxDirective[];
}

/** A parsed `upstream` block. */
export interface NginxUpstream {
  name: string;
  /** Server entries as "ip:port" strings. */
  servers: string[];
}

/** A parsed `server` block. */
export interface NginxServer {
  serverNames: string[];
  listen: string[];
  ssl: boolean;
  locations: NginxLocation[];
  directives: NginxDirective[];
}

/** A diagnostic message produced during parsing. */
export interface NginxDiagnostic {
  level: 'info' | 'warning' | 'error';
  line: number;
  message: string;
  directive?: string;
}

/** Top-level result of parsing an Nginx config string. */
export interface NginxParseResult {
  servers: NginxServer[];
  upstreams: NginxUpstream[];
  diagnostics: NginxDiagnostic[];
}

/** A path rule derived from an Nginx location block. */
export interface PathRuleImport {
  path: string;
  match_type: 'prefix' | 'exact';
  backend_addresses?: string[];
  cache_enabled?: boolean;
  cache_ttl_s?: number;
  response_headers?: Record<string, string>;
  response_headers_remove?: string[];
  rate_limit_rps?: number;
  rate_limit_burst?: number;
  redirect_to?: string;
  return_status?: number;
}

/** A Lorica route derived from parsed Nginx config. */
export interface LoricaRouteImport {
  hostname: string;
  path_prefix: string;
  hostname_aliases: string[];
  force_https: boolean;
  backend_addresses: string[];
  certificate_needed: boolean;
  proxy_headers: Record<string, string>;
  response_headers: Record<string, string>;
  proxy_headers_remove: string[];
  response_headers_remove: string[];
  connect_timeout_s: number;
  read_timeout_s: number;
  send_timeout_s: number;
  max_request_body_bytes: number | null;
  security_headers: string;
  /** Security headers detected during import, for preset matching. */
  _securityHeaders?: Record<string, string>;
  /** Backends need tls_skip_verify (detected from proxy_pass https:// or proxy_ssl_verify off). */
  _backendTlsSkipVerify?: boolean;
  strip_path_prefix: string | null;
  add_path_prefix: string | null;
  path_rewrite_pattern: string | null;
  path_rewrite_replacement: string | null;
  redirect_to: string | null;
  redirect_hostname: string | null;
  rate_limit_rps: number | null;
  rate_limit_burst: number | null;
  cache_enabled: boolean;
  cache_ttl_s: number;
  path_rules: PathRuleImport[];
  return_status: number | null;
  /** Detected ssl_certificate path from Nginx config. */
  _sslCertPath?: string;
  /** Detected ssl_certificate_key path from Nginx config. */
  _sslKeyPath?: string;
  /** Tracks which fields were explicitly imported (vs defaults). */
  importedFields: Set<string>;
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/**
 * Convert an Nginx time string to seconds.
 *
 * Supports formats: "30", "30s", "2m", "1h", "1d".
 * A bare number without suffix is treated as seconds.
 *
 * @param s - Nginx time value
 * @returns Duration in seconds, or 0 if unparseable
 */
export function parseNginxTime(s: string): number {
  const trimmed = s.trim();
  const match = trimmed.match(/^(\d+)\s*([smhd]?)$/i);
  if (!match) return 0;
  const value = parseInt(match[1], 10);
  switch (match[2].toLowerCase()) {
    case '':
    case 's':
      return value;
    case 'm':
      return value * 60;
    case 'h':
      return value * 3600;
    case 'd':
      return value * 86400;
    default:
      return 0;
  }
}

/**
 * Convert an Nginx size string to bytes.
 *
 * Supports formats: "100", "10k", "10m", "1g" (case-insensitive).
 * A bare number without suffix is treated as bytes.
 *
 * @param s - Nginx size value
 * @returns Size in bytes, or 0 if unparseable
 */
export function parseNginxSize(s: string): number {
  const trimmed = s.trim();
  const match = trimmed.match(/^(\d+)\s*([kmg]?)$/i);
  if (!match) return 0;
  const value = parseInt(match[1], 10);
  switch (match[2].toLowerCase()) {
    case '':
      return value;
    case 'k':
      return value * 1024;
    case 'm':
      return value * 1024 * 1024;
    case 'g':
      return value * 1024 * 1024 * 1024;
    default:
      return 0;
  }
}

/**
 * Extract "host:port" from a proxy_pass URL.
 *
 * Handles formats like:
 * - `http://127.0.0.1:8080`
 * - `http://127.0.0.1:8080/path`
 * - `http://backend_name`
 * - `https://example.com`
 *
 * @param proxyPass - The full proxy_pass value
 * @returns "host:port" string, or just "host" if no port specified
 */
export function extractHostPort(proxyPass: string): string {
  const trimmed = proxyPass.trim().replace(/;$/, '');
  // Strip scheme
  const withoutScheme = trimmed.replace(/^https?:\/\//, '');
  // Strip path
  const hostPort = withoutScheme.split('/')[0];
  return hostPort;
}

// ---------------------------------------------------------------------------
// Security header detection
// ---------------------------------------------------------------------------

const SECURITY_HEADER_NAMES = new Set([
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'x-xss-protection',
  'referrer-policy',
  'content-security-policy',
  'permissions-policy',
]);

/**
 * Check whether a header name is a well-known security header.
 *
 * @param name - Header name (case-insensitive)
 */
function isSecurityHeader(name: string): boolean {
  return SECURITY_HEADER_NAMES.has(name.toLowerCase());
}

// ---------------------------------------------------------------------------
// Directive mapping
// ---------------------------------------------------------------------------

type DirectiveHandler = (
  value: string,
  route: LoricaRouteImport,
  diagnostics: NginxDiagnostic[],
  line: number,
) => void;

/**
 * Map of Nginx directive names to handler functions that populate
 * a LoricaRouteImport.
 */
const DIRECTIVE_MAP: Record<string, DirectiveHandler> = {
  server_name: (v, r) => {
    const names = v.split(/\s+/).filter(Boolean);
    if (names.length > 0) {
      r.hostname = names[0];
      r.hostname_aliases = names.slice(1);
      r.importedFields.add('hostname');
      if (names.length > 1) r.importedFields.add('hostname_aliases');
    }
  },

  proxy_pass: (v, r) => {
    r.backend_addresses.push(extractHostPort(v));
    r.importedFields.add('backend_addresses');
    // Detect HTTPS backend (proxy_pass https://...)
    if (v.trim().startsWith('https://')) {
      r._backendTlsSkipVerify = true;
    }
  },

  proxy_ssl_verify: (v, r) => {
    if (v.trim() === 'off') {
      r._backendTlsSkipVerify = true;
    }
  },

  proxy_read_timeout: (v, r) => {
    r.read_timeout_s = parseNginxTime(v);
    r.importedFields.add('read_timeout_s');
  },

  proxy_send_timeout: (v, r) => {
    r.send_timeout_s = parseNginxTime(v);
    r.importedFields.add('send_timeout_s');
  },

  proxy_connect_timeout: (v, r) => {
    r.connect_timeout_s = parseNginxTime(v);
    r.importedFields.add('connect_timeout_s');
  },

  proxy_set_header: (v, r) => {
    const parts = v.split(/\s+/);
    const key = parts[0];
    const rest = parts.slice(1).join(' ');
    if (!key) return;
    // Skip headers whose values are Nginx variables that Lorica handles natively.
    // Lorica automatically forwards Host, X-Real-IP, X-Forwarded-For, X-Forwarded-Proto.
    // Importing literal "$http_host" would break upstream requests.
    const nativelyHandled: Record<string, string[]> = {
      'Host': ['$host', '$http_host'],
      'X-Real-IP': ['$remote_addr', '$http_cf_connecting_ip'],
      'X-Forwarded-For': ['$proxy_add_x_forwarded_for'],
      'X-Forwarded-Proto': ['$scheme', 'https', 'http'],
      'X-Forwarded-Host': ['$host', '$http_host'],
      'X-Forwarded-Port': ['$server_port'],
      'Connection': ['""', '"Upgrade"', 'upgrade', '$connection_upgrade', '"upgrade"', '""'],
      'Upgrade': ['$http_upgrade'],
    };
    const skipVars = nativelyHandled[key];
    if (skipVars && skipVars.some(sv => rest.trim().toLowerCase() === sv.toLowerCase())) {
      return; // Lorica handles this header automatically
    }
    // Skip any header value that is purely an Nginx variable
    if (/^\$\w+$/.test(rest.trim())) {
      return; // Pure Nginx variable, not a static value
    }
    r.proxy_headers[key] = rest;
    r.importedFields.add('proxy_headers');
  },

  proxy_hide_header: (v, r) => {
    r.proxy_headers_remove.push(v.trim());
    r.importedFields.add('proxy_headers_remove');
  },

  add_header: (v, r) => {
    // Parse: add_header Name "value with spaces" [always]
    // The value may be quoted and contain semicolons
    const trimmed = v.trim().replace(/\s+always\s*$/, '');
    const spaceIdx = trimmed.indexOf(' ');
    if (spaceIdx === -1) return;
    const key = trimmed.substring(0, spaceIdx);
    let val = trimmed.substring(spaceIdx + 1).trim();
    // Strip surrounding quotes
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (key) {
      if (isSecurityHeader(key)) {
        // Track security headers separately for preset matching during import
        if (!r._securityHeaders) r._securityHeaders = {};
        r._securityHeaders[key] = val;
        r.security_headers = 'auto';
        r.importedFields.add('security_headers');
      } else {
        r.response_headers[key] = val;
        r.importedFields.add('response_headers');
      }
    }
  },

  client_max_body_size: (v, r) => {
    r.max_request_body_bytes = parseNginxSize(v);
    r.importedFields.add('max_request_body_bytes');
  },

  limit_req: (v, r) => {
    const burst = v.match(/burst=(\d+)/);
    if (burst) {
      r.rate_limit_burst = parseInt(burst[1], 10);
      r.importedFields.add('rate_limit_burst');
    }
    const rate = v.match(/rate=(\d+)r\/s/);
    if (rate) {
      r.rate_limit_rps = parseInt(rate[1], 10);
      r.importedFields.add('rate_limit_rps');
    }
  },

  return: (v, r) => {
    // Handle bare status codes: "return 403", "return 404"
    const bareStatus = v.match(/^(\d{3})\s*$/);
    if (bareStatus) {
      const status = parseInt(bareStatus[1], 10);
      r.return_status = status;
      r.importedFields.add('return_status');
      return;
    }

    const match301 = v.match(/^30[12]\s+(https?:\/\/.+)/);
    if (match301) {
      let target = match301[1].replace(/\$request_uri\s*$/, '').replace(/;$/, '').trim();

      // Nginx variables ($host, $server_name, $http_host) = same host -> force_https
      if (/\$host|\$server_name|\$http_host/.test(target)) {
        r.force_https = true;
        r.importedFields.add('force_https');
        return;
      }

      // Determine if this is a same-host force_https or a different-host redirect_to
      try {
        const url = new URL(target);
        const currentHostnames = [r.hostname, ...r.hostname_aliases].filter(Boolean);
        if (url.protocol === 'https:' && currentHostnames.includes(url.hostname) && url.pathname === '/') {
          r.force_https = true;
          r.importedFields.add('force_https');
        } else {
          // Strip trailing slash from target for clean append
          r.redirect_to = target.replace(/\/$/, '') || target;
          r.importedFields.add('redirect_to');
        }
      } catch {
        // If URL parsing fails, treat as force_https if it looks like same-host HTTPS
        if (v.startsWith('301 https://') || v.startsWith('302 https://')) {
          r.force_https = true;
          r.importedFields.add('force_https');
        }
      }
    }
  },

  proxy_cache: (v, r) => {
    if (v !== 'off') {
      r.cache_enabled = true;
      r.importedFields.add('cache_enabled');
    }
  },

  proxy_cache_valid: (v, r) => {
    // Format: "200 302 10m" or "any 5m" or "10m"
    const parts = v.trim().split(/\s+/);
    const timePart = parts[parts.length - 1];
    if (timePart) {
      r.cache_ttl_s = parseNginxTime(timePart);
      r.cache_enabled = true;
      r.importedFields.add('cache_ttl_s');
      r.importedFields.add('cache_enabled');
    }
  },

  include: (_v, _r, d, line) => {
    d.push({
      level: 'error',
      line,
      message: `Unresolved include: ${_v}. Paste file contents to resolve.`,
      directive: 'include',
    });
  },

  ssl_certificate: (v, r) => {
    r.certificate_needed = true;
    r._sslCertPath = v.trim();
    r.importedFields.add('certificate_needed');
  },

  ssl_certificate_key: (v, r) => {
    r.certificate_needed = true;
    r._sslKeyPath = v.trim();
    r.importedFields.add('certificate_needed');
  },

  rewrite: (v, r) => {
    // Parse: rewrite <pattern> <replacement> [flag];
    // Example: rewrite ^/api/v1/(.*) /v2/$1 break;
    const parts = v.replace(/;$/, '').trim().split(/\s+/);
    if (parts.length < 2) return;

    const pattern = parts[0];
    const replacement = parts[1];

    // Simple case: rewrite ^/prefix/(.*) /$1 -> strip_path_prefix
    const stripMatch = pattern.match(/^\^?(\/.+?)\/(.*?)\s*$/) ||
                       pattern.match(/^\^(\/.+?)\/\(\.\*\)$/);
    if (stripMatch && replacement === '/$1') {
      r.strip_path_prefix = stripMatch[1];
      r.importedFields.add('strip_path_prefix');
      return;
    }

    // General regex rewrite -> path_rewrite_pattern + path_rewrite_replacement
    // Convert PCRE to Rust regex (basic: they are mostly compatible)
    if (pattern && replacement) {
      r.path_rewrite_pattern = pattern;
      r.path_rewrite_replacement = replacement;
      r.importedFields.add('path_rewrite_pattern');
      r.importedFields.add('path_rewrite_replacement');
    }
  },
};

// ---------------------------------------------------------------------------
// Tokenizer - line-based parser
// ---------------------------------------------------------------------------

/** Represents a block type during parsing. */
type BlockType = 'root' | 'server' | 'upstream' | 'location' | 'other';

interface BlockFrame {
  type: BlockType;
  name: string;
  startLine: number;
}

/**
 * Check if a character appears outside of quoted strings.
 *
 * @param line - The line to check
 * @param ch - The character to look for
 * @returns true if ch appears outside quotes
 */
function hasUnquotedChar(line: string, ch: string): boolean {
  let inDouble = false;
  let inSingle = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"' && !inSingle) inDouble = !inDouble;
    else if (c === "'" && !inDouble) inSingle = !inSingle;
    else if (c === ch && !inDouble && !inSingle) return true;
  }
  return false;
}

/**
 * Strip inline comments from a line.
 *
 * Handles the case where `#` appears inside a quoted string (keeps it).
 * For simplicity, treats the first `#` not inside quotes as the comment start.
 *
 * @param line - Raw config line
 * @returns Line with comments removed
 */
function stripComment(line: string): string {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === '#' && !inSingle && !inDouble) {
      return line.substring(0, i);
    }
  }
  return line;
}

/**
 * Split a line into individual statements on semicolons, keeping
 * brace-only segments separate. Respects quoted strings so that
 * semicolons inside quotes (e.g. HSTS directives) are not treated
 * as statement terminators.
 *
 * @param line - Cleaned config line
 * @returns Array of statement strings
 */
function splitStatements(line: string): string[] {
  const results: string[] = [];
  let current = '';
  let inDouble = false;
  let inSingle = false;
  for (const ch of line) {
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      current += ch;
    } else if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      current += ch;
    } else if (!inDouble && !inSingle && ch === ';') {
      const trimmed = current.trim();
      if (trimmed) results.push(trimmed);
      current = '';
    } else if (!inDouble && !inSingle && (ch === '{' || ch === '}')) {
      const trimmed = current.trim();
      if (trimmed) results.push(trimmed);
      results.push(ch);
      current = '';
    } else {
      current += ch;
    }
  }
  const trimmed = current.trim();
  if (trimmed) results.push(trimmed);
  return results;
}

/**
 * Parse a directive string "name value1 value2" into name and value parts.
 *
 * @param stmt - A single directive statement (without semicolon)
 * @returns Tuple of [name, value]
 */
function parseDirectiveString(stmt: string): [string, string] {
  const spaceIdx = stmt.indexOf(' ');
  if (spaceIdx === -1) return [stmt, ''];
  return [stmt.substring(0, spaceIdx), stmt.substring(spaceIdx + 1).trim()];
}

// ---------------------------------------------------------------------------
// Core parser
// ---------------------------------------------------------------------------

/**
 * Parse an Nginx configuration string into a structured result.
 *
 * This is a line-based parser that:
 * 1. Strips comments
 * 2. Tracks brace depth to identify blocks
 * 3. Splits directives by semicolons
 * 4. Handles multi-line directives (continuation when no semicolon)
 *
 * @param text - Raw Nginx configuration text
 * @returns Parsed result with servers, upstreams, and diagnostics
 */
export function parseNginxConfig(text: string): NginxParseResult {
  const servers: NginxServer[] = [];
  const upstreams: NginxUpstream[] = [];
  const diagnostics: NginxDiagnostic[] = [];

  const blockStack: BlockFrame[] = [{ type: 'root', name: '', startLine: 0 }];

  // Current objects being built
  let currentServer: NginxServer | null = null;
  let currentUpstream: NginxUpstream | null = null;
  let currentLocation: NginxLocation | null = null;

  // Multi-line directive accumulator
  let pendingLine = '';
  let pendingLineNumber = 0;

  // Track seen directives per block for duplicate detection
  const seenDirectives = new Map<string, { value: string; line: number }>();

  const lines = text.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const lineNumber = i + 1;
    const raw = lines[i];
    const cleaned = stripComment(raw).trim();

    if (!cleaned) continue;

    // Detect extra semicolons
    if (cleaned.includes(';;')) {
      diagnostics.push({
        level: 'warning',
        line: lineNumber,
        message: 'Extra semicolon detected.',
      });
    }

    // Handle multi-line continuation: if the previous line had no semicolon
    // and no brace, accumulate.
    let lineToProcess: string;
    if (pendingLine) {
      lineToProcess = pendingLine + ' ' + cleaned;
    } else {
      lineToProcess = cleaned;
    }

    // Check if line is complete (has semicolon or brace outside quotes)
    const hasSemicolon = hasUnquotedChar(lineToProcess, ';');
    const hasBrace = hasUnquotedChar(lineToProcess, '{') || hasUnquotedChar(lineToProcess, '}');
    if (!hasSemicolon && !hasBrace) {
      pendingLine = lineToProcess;
      if (!pendingLineNumber) pendingLineNumber = lineNumber;
      continue;
    }

    const effectiveLine = pendingLineNumber || lineNumber;
    pendingLine = '';
    pendingLineNumber = 0;

    const statements = splitStatements(lineToProcess);

    for (const stmt of statements) {
      if (stmt === '{') {
        // Opening brace already handled by the block-opening statement
        continue;
      }

      if (stmt === '}') {
        const frame = blockStack.pop();
        if (!frame || frame.type === 'root') {
          diagnostics.push({
            level: 'error',
            line: effectiveLine,
            message: 'Unexpected closing brace.',
          });
          if (frame) blockStack.push(frame);
          continue;
        }

        if (frame.type === 'location' && currentLocation) {
          if (currentServer) {
            currentServer.locations.push(currentLocation);
          }
          currentLocation = null;
        } else if (frame.type === 'server' && currentServer) {
          servers.push(currentServer);
          currentServer = null;
          seenDirectives.clear();
        } else if (frame.type === 'upstream' && currentUpstream) {
          upstreams.push(currentUpstream);
          currentUpstream = null;
        }
        continue;
      }

      const [name, value] = parseDirectiveString(stmt);
      const nameLower = name.toLowerCase();

      // Block-opening directives
      if (nameLower === 'server' && (value === '' || value === '{')) {
        currentServer = {
          serverNames: [],
          listen: [],
          ssl: false,
          locations: [],
          directives: [],
        };
        seenDirectives.clear();
        blockStack.push({ type: 'server', name: '', startLine: effectiveLine });
        continue;
      }

      if (nameLower === 'upstream') {
        const upstreamName = value.replace(/\s*\{?\s*$/, '').trim();
        currentUpstream = { name: upstreamName, servers: [] };
        blockStack.push({ type: 'upstream', name: upstreamName, startLine: effectiveLine });
        continue;
      }

      if (nameLower === 'location') {
        const locPath = value
          .replace(/\s*\{?\s*$/, '')
          .replace(/^[~=^]+\s*/, '') // Strip modifiers like ~, ~*, =, ^~
          .trim();
        currentLocation = { path: locPath || '/', proxyPass: null, directives: [] };
        blockStack.push({ type: 'location', name: locPath, startLine: effectiveLine });
        continue;
      }

      // Warn about unsupported 'if' blocks
      if (nameLower === 'if') {
        diagnostics.push({
          level: 'warning',
          line: effectiveLine,
          message: 'Conditional "if" block skipped. Most applications handle this logic internally - verify behavior after import.',
        });
        blockStack.push({ type: 'other', name: nameLower, startLine: effectiveLine });
        continue;
      }

      // Skip block types we do not specifically handle
      if (value.endsWith('{') || value === '{') {
        blockStack.push({ type: 'other', name: nameLower, startLine: effectiveLine });
        continue;
      }

      const currentFrame = blockStack[blockStack.length - 1];
      const directive: NginxDirective = { name: nameLower, value, line: effectiveLine };

      // Duplicate detection (only within server blocks, skip repeatable directives)
      const repeatableDirectives = new Set([
        'listen',
        'server_name',
        'proxy_set_header',
        'proxy_hide_header',
        'add_header',
        'limit_req',
        'include',
        'rewrite',
        'proxy_cache_valid',
      ]);
      if (
        currentFrame?.type === 'server' &&
        !repeatableDirectives.has(nameLower)
      ) {
        const prev = seenDirectives.get(nameLower);
        if (prev) {
          diagnostics.push({
            level: 'warning',
            line: effectiveLine,
            message: `Duplicate directive "${nameLower}": previous value "${prev.value}" at line ${prev.line}, new value "${value}".`,
            directive: nameLower,
          });
        }
        seenDirectives.set(nameLower, { value, line: effectiveLine });
      }

      // Place directive in the right container
      if (currentFrame?.type === 'upstream' && currentUpstream) {
        if (nameLower === 'server') {
          // Upstream server entry: "ip:port weight=N" - keep just the address
          const addr = value.split(/\s+/)[0];
          currentUpstream.servers.push(addr);
        }
      } else if (currentFrame?.type === 'location' && currentLocation) {
        currentLocation.directives.push(directive);
        if (nameLower === 'proxy_pass') {
          currentLocation.proxyPass = value;
        }
      } else if (currentFrame?.type === 'server' && currentServer) {
        currentServer.directives.push(directive);
        if (nameLower === 'listen') {
          currentServer.listen.push(value);
          if (value.includes('ssl')) {
            currentServer.ssl = true;
          }
          // Check for non-standard ports
          const portMatch = value.match(/(\d+)/);
          if (portMatch) {
            const port = parseInt(portMatch[1], 10);
            if (port !== 80 && port !== 443) {
              diagnostics.push({
                level: 'warning',
                line: effectiveLine,
                message: `Non-standard port ${port} detected. Lorica listens on 80/443 only. Consider using a subdomain on port 443 instead.`,
              });
            }
          }
        } else if (nameLower === 'server_name') {
          currentServer.serverNames = value.split(/\s+/).filter(Boolean);
        } else if (nameLower === 'ssl' && value === 'on') {
          currentServer.ssl = true;
        }
      }
    }
  }

  // Check for unclosed blocks
  if (blockStack.length > 1) {
    for (let j = blockStack.length - 1; j >= 1; j--) {
      diagnostics.push({
        level: 'error',
        line: blockStack[j].startLine,
        message: `Unclosed ${blockStack[j].type} block.`,
      });
    }
  }

  return { servers, upstreams, diagnostics };
}

// ---------------------------------------------------------------------------
// Conversion to Lorica routes
// ---------------------------------------------------------------------------

/**
 * Create a new LoricaRouteImport with default values.
 *
 * @returns Fresh route with all fields set to safe defaults
 */
function createDefaultRoute(): LoricaRouteImport {
  return {
    hostname: '',
    path_prefix: '/',
    hostname_aliases: [],
    force_https: false,
    backend_addresses: [],
    certificate_needed: false,
    proxy_headers: {},
    response_headers: {},
    proxy_headers_remove: [],
    response_headers_remove: [],
    connect_timeout_s: 5,
    read_timeout_s: 30,
    send_timeout_s: 30,
    max_request_body_bytes: null,
    security_headers: 'none',
    strip_path_prefix: null,
    add_path_prefix: null,
    path_rewrite_pattern: null,
    path_rewrite_replacement: null,
    redirect_to: null,
    redirect_hostname: null,
    rate_limit_rps: null,
    rate_limit_burst: null,
    cache_enabled: false,
    cache_ttl_s: 0,
    path_rules: [],
    return_status: null,
    importedFields: new Set<string>(),
  };
}

/**
 * Nginx directives handled by Lorica internally, with human-readable descriptions.
 * These are NOT mapped to Lorica route fields but are recognized and annotated
 * in the resolved config view instead of showing "unknown".
 */
export const LORICA_HANDLED_DIRECTIVES: Record<string, string> = {
  // TLS/SSL - Lorica manages TLS termination
  listen: 'Lorica: HTTP/HTTPS ports',
  http2: 'Lorica: HTTP/2 auto',
  ssl: 'Lorica: TLS managed',
  ssl_dhparam: 'Lorica: TLS managed',
  ssl_protocols: 'Lorica: TLS managed',
  ssl_ciphers: 'Lorica: TLS managed',
  ssl_prefer_server_ciphers: 'Lorica: TLS managed',
  ssl_session_cache: 'Lorica: TLS managed',
  ssl_session_timeout: 'Lorica: TLS managed',
  ssl_session_tickets: 'Lorica: TLS managed',
  ssl_session_ticket_key: 'Lorica: TLS managed',
  ssl_stapling: 'Lorica: TLS managed',
  ssl_stapling_verify: 'Lorica: TLS managed',
  ssl_trusted_certificate: 'Lorica: TLS managed',
  ssl_verify_client: 'Lorica: TLS managed',
  ssl_verify_depth: 'Lorica: TLS managed',
  ssl_client_certificate: 'Lorica: TLS managed',
  ssl_crl: 'Lorica: CRL via CLI flag',
  ssl_ecdh_curve: 'Lorica: TLS managed',
  ssl_buffer_size: 'Lorica: TLS managed',
  ssl_password_file: 'Lorica: TLS managed',
  ssl_early_data: 'Lorica: TLS managed',
  ssl_reject_handshake: 'Lorica: TLS managed',
  ssl_conf_command: 'Lorica: TLS managed',
  // Proxy connection
  proxy_http_version: 'Lorica: HTTP/1.1 auto',
  proxy_buffering: 'Lorica: internal',
  proxy_buffer_size: 'Lorica: internal',
  proxy_buffers: 'Lorica: internal',
  proxy_busy_buffers_size: 'Lorica: internal',
  proxy_max_temp_file_size: 'Lorica: internal',
  proxy_temp_file_write_size: 'Lorica: internal',
  proxy_request_buffering: 'Lorica: internal',
  proxy_temp_path: 'Lorica: internal',
  proxy_redirect: 'Lorica: internal',
  proxy_next_upstream: 'Lorica: retry_attempts',
  proxy_next_upstream_tries: 'Lorica: retry_attempts',
  proxy_next_upstream_timeout: 'Lorica: retry_attempts',
  proxy_intercept_errors: 'Lorica: internal',
  proxy_pass_request_headers: 'Lorica: internal',
  proxy_pass_request_body: 'Lorica: internal',
  proxy_headers_hash_max_size: 'Lorica: internal',
  proxy_headers_hash_bucket_size: 'Lorica: internal',
  proxy_ssl_server_name: 'Lorica: tls_sni on backend',
  proxy_ssl_name: 'Lorica: tls_sni on backend',
  // proxy_ssl_verify is in DIRECTIVE_MAP (sets _backendTlsSkipVerify)
  proxy_ssl_certificate: 'Lorica: internal',
  proxy_ssl_certificate_key: 'Lorica: internal',
  proxy_ssl_protocols: 'Lorica: internal',
  proxy_ssl_ciphers: 'Lorica: internal',
  proxy_ssl_session_reuse: 'Lorica: internal',
  proxy_ssl_trusted_certificate: 'Lorica: internal',
  proxy_cookie_domain: 'ignored: cookie rewrite',
  proxy_cookie_path: 'ignored: cookie rewrite',
  proxy_cookie_flags: 'ignored: cookie flags',
  proxy_socket_keepalive: 'Lorica: connection pooling',
  chunked_transfer_encoding: 'Lorica: internal',
  proxy_bind: 'ignored: not applicable',
  proxy_ignore_headers: 'ignored: not applicable',
  proxy_force_ranges: 'ignored: not applicable',
  proxy_limit_rate: 'ignored: not applicable',
  proxy_method: 'ignored: not applicable',
  proxy_set_body: 'ignored: not applicable',
  proxy_pass_header: 'ignored: not applicable',
  // Upstream/connection
  keepalive: 'Lorica: connection pooling',
  keepalive_timeout: 'Lorica: connection pooling',
  keepalive_requests: 'Lorica: connection pooling',
  // Logging
  access_log: 'Lorica: own access logs',
  error_log: 'Lorica: own error logs',
  log_format: 'Lorica: own log format',
  log_not_found: 'ignored: not applicable',
  log_subrequest: 'ignored: not applicable',
  open_log_file_cache: 'ignored: not applicable',
  // Compression
  gzip: 'Lorica: compression_enabled',
  gzip_types: 'Lorica: compression auto',
  gzip_vary: 'Lorica: compression auto',
  gzip_proxied: 'Lorica: compression auto',
  gzip_comp_level: 'Lorica: compression auto',
  gzip_min_length: 'Lorica: compression auto',
  gzip_disable: 'Lorica: compression auto',
  gzip_buffers: 'Lorica: compression auto',
  gzip_http_version: 'Lorica: compression auto',
  gzip_static: 'ignored: static files',
  brotli: 'ignored: not supported',
  brotli_types: 'ignored: not supported',
  brotli_comp_level: 'ignored: not supported',
  brotli_min_length: 'ignored: not supported',
  brotli_static: 'ignored: static files',
  // Server/networking
  sendfile: 'ignored: kernel optimization',
  tcp_nopush: 'ignored: kernel optimization',
  tcp_nodelay: 'ignored: kernel optimization',
  resolver: 'Lorica: system DNS',
  resolver_timeout: 'Lorica: system DNS',
  charset: 'ignored: not applicable',
  server_tokens: 'Lorica: no server token',
  send_timeout: 'Lorica: send_timeout_s',
  types_hash_max_size: 'ignored: internal',
  variables_hash_max_size: 'ignored: internal',
  reset_timedout_connection: 'ignored: internal',
  lingering_close: 'ignored: internal',
  lingering_time: 'ignored: internal',
  lingering_timeout: 'ignored: internal',
  // Static files (not applicable to RP)
  root: 'ignored: static files',
  alias: 'ignored: static files',
  index: 'ignored: static files',
  try_files: 'ignored: static files',
  autoindex: 'ignored: static files',
  expires: 'ignored: static files',
  etag: 'ignored: static files',
  if_modified_since: 'ignored: static files',
  open_file_cache: 'ignored: static files',
  open_file_cache_valid: 'ignored: static files',
  open_file_cache_min_uses: 'ignored: static files',
  types: 'ignored: not applicable',
  default_type: 'ignored: not applicable',
  // Client limits
  client_body_timeout: 'Lorica: read_timeout_s',
  client_header_timeout: 'Lorica: internal',
  client_body_buffer_size: 'Lorica: internal',
  client_header_buffer_size: 'Lorica: internal',
  large_client_header_buffers: 'Lorica: internal',
  // FastCGI/uwsgi/SCGI (backend-specific, not proxied)
  fastcgi_pass: 'ignored: direct backend',
  fastcgi_param: 'ignored: direct backend',
  fastcgi_buffers: 'ignored: direct backend',
  fastcgi_buffer_size: 'ignored: direct backend',
  fastcgi_max_temp_file_size: 'ignored: direct backend',
  fastcgi_connect_timeout: 'ignored: direct backend',
  fastcgi_send_timeout: 'ignored: direct backend',
  fastcgi_read_timeout: 'ignored: direct backend',
  uwsgi_pass: 'ignored: direct backend',
  uwsgi_param: 'ignored: direct backend',
  scgi_pass: 'ignored: direct backend',
  grpc_pass: 'ignored: not supported',
  grpc_set_header: 'ignored: not supported',
  // Rate limiting zones (handled differently)
  limit_req_zone: 'Lorica: rate_limit_rps',
  limit_conn: 'Lorica: max_connections',
  limit_conn_zone: 'Lorica: max_connections',
  limit_rate: 'ignored: not applicable',
  limit_rate_after: 'ignored: not applicable',
  // Auth
  auth_basic: 'ignored: not applicable',
  auth_basic_user_file: 'ignored: not applicable',
  auth_request: 'ignored: not applicable',
  auth_request_set: 'ignored: not applicable',
  satisfy: 'ignored: not applicable',
  allow: 'Lorica: ip_allowlist',
  deny: 'Lorica: ip_denylist',
  // Misc
  error_page: 'ignored: not applicable',
  map: 'ignored: not applicable',
  set: 'ignored: not applicable',
  geo: 'ignored: not applicable',
  sub_filter: 'ignored: not applicable',
  sub_filter_once: 'ignored: not applicable',
  sub_filter_types: 'ignored: not applicable',
  mirror: 'ignored: not applicable',
  mirror_request_body: 'ignored: not applicable',
  real_ip_header: 'Lorica: X-Real-IP auto',
  set_real_ip_from: 'Lorica: trusted proxy',
  real_ip_recursive: 'Lorica: internal',
  more_set_headers: 'Lorica: response_headers',
  more_clear_headers: 'Lorica: response_headers_remove',
  // Upstream block directives (handled at block level, not directive level)
  zone: 'ignored: upstream config',
  least_conn: 'Lorica: load_balancing',
  ip_hash: 'Lorica: load_balancing',
  hash: 'Lorica: load_balancing',
  // Proxy cache (advanced directives beyond basic)
  proxy_cache_path: 'Lorica: cache internal',
  proxy_cache_bypass: 'Lorica: cache internal',
  proxy_cache_use_stale: 'Lorica: cache internal',
  proxy_cache_lock: 'Lorica: cache internal',
  proxy_cache_min_uses: 'Lorica: cache internal',
  proxy_cache_methods: 'Lorica: cache internal',
  proxy_no_cache: 'Lorica: cache internal',
  proxy_cache_revalidate: 'Lorica: cache internal',
  proxy_cache_background_update: 'Lorica: cache internal',
  proxy_cache_key: 'Lorica: cache internal',
};

/**
 * Apply a directive to a route using the DIRECTIVE_MAP.
 *
 * Directives in LORICA_HANDLED_DIRECTIVES are silently skipped (annotated in
 * the resolved config view). All other unrecognized directives are silently
 * ignored - no "unknown" diagnostic is generated since the list of Nginx
 * directives and third-party modules is effectively unbounded.
 *
 * @param directive - The parsed directive
 * @param route - The route being built
 * @param diagnostics - Diagnostic accumulator
 */
function applyDirective(
  directive: NginxDirective,
  route: LoricaRouteImport,
  diagnostics: NginxDiagnostic[],
): void {
  const handler = DIRECTIVE_MAP[directive.name];
  if (handler) {
    handler(directive.value, route, diagnostics, directive.line);
  }
  // All other directives (LORICA_HANDLED_DIRECTIVES or truly unknown) are
  // silently skipped. The resolved config view handles annotations via
  // getAnnotation() which checks both DIRECTIVE_MAP and LORICA_HANDLED_DIRECTIVES.
}

/**
 * Resolve upstream references in backend addresses.
 *
 * If a backend address matches an upstream name, replace it with
 * the upstream's server list.
 *
 * @param route - Route with potentially unresolved upstream refs
 * @param upstreams - Parsed upstream blocks
 */
function resolveUpstreams(
  route: LoricaRouteImport,
  upstreams: NginxUpstream[],
): void {
  const upstreamMap = new Map<string, NginxUpstream>();
  for (const u of upstreams) {
    upstreamMap.set(u.name, u);
  }

  const resolved: string[] = [];
  for (const addr of route.backend_addresses) {
    const upstream = upstreamMap.get(addr);
    if (upstream) {
      resolved.push(...upstream.servers);
    } else {
      resolved.push(addr);
    }
  }
  route.backend_addresses = resolved;
}

/**
 * Merge related routes that represent the same logical site.
 *
 * Handles two common Nginx patterns:
 * 1. HTTP-to-HTTPS redirect: a server block with `return 301 https://...`
 *    and no backends is merged into the corresponding HTTPS route.
 * 2. www-to-bare redirect: a server block for `www.X` that redirects to `X`
 *    is merged into the `X` route as a hostname alias with redirect_hostname.
 *
 * @param routes - Array of routes produced by per-server-block conversion
 * @returns Deduplicated array with merged configuration
 */
export function mergeRelatedRoutes(routes: LoricaRouteImport[]): LoricaRouteImport[] {
  // Index routes by hostname for fast lookup
  const byHostname = new Map<string, LoricaRouteImport[]>();
  for (const r of routes) {
    const key = r.hostname.toLowerCase();
    if (!byHostname.has(key)) byHostname.set(key, []);
    byHostname.get(key)!.push(r);
  }

  // --- Pass 1: Merge HTTP redirect-only routes into HTTPS routes ---
  // A "redirect-only" route has force_https=true, no backends, and no redirect_to.
  const removedIndices = new Set<number>();

  for (const [hostname, group] of byHostname) {
    if (group.length < 2) continue;

    for (const redirectRoute of group) {
      if (!redirectRoute.force_https) continue;
      if (redirectRoute.backend_addresses.length > 0) continue;
      if (redirectRoute.redirect_to) continue;

      // Find a primary route with the same hostname + path_prefix that has backends
      for (const primary of group) {
        if (primary === redirectRoute) continue;
        if (primary.path_prefix !== redirectRoute.path_prefix) continue;
        if (primary.backend_addresses.length === 0) continue;

        // Merge: set force_https on the primary, absorb aliases
        primary.force_https = true;
        primary.importedFields.add('force_https');
        for (const alias of redirectRoute.hostname_aliases) {
          if (!primary.hostname_aliases.includes(alias) && alias.toLowerCase() !== hostname) {
            primary.hostname_aliases.push(alias);
          }
        }
        if (primary.hostname_aliases.length > 0) {
          primary.importedFields.add('hostname_aliases');
        }

        // Mark the redirect-only route for removal
        removedIndices.add(routes.indexOf(redirectRoute));
        break;
      }
    }
  }

  // --- Pass 2: Merge www redirect routes into bare domain routes ---
  // A www redirect route: hostname is www.X and has redirect_to pointing to X
  for (let i = 0; i < routes.length; i++) {
    if (removedIndices.has(i)) continue;
    const route = routes[i];
    const host = route.hostname.toLowerCase();

    if (!host.startsWith('www.')) continue;
    const bareDomain = host.slice(4);

    // Check if this route is a redirect to the bare domain
    const isWwwRedirect = (() => {
      if (route.redirect_to) {
        // redirect_to could be "https://X", "http://X", or just "X"
        const target = route.redirect_to.toLowerCase();
        if (
          target === `https://${bareDomain}` ||
          target === `http://${bareDomain}` ||
          target === bareDomain
        ) {
          return true;
        }
      }
      // Also detect force_https routes for www.X with no backends and no redirect_to
      // (these are essentially www->bare redirects when paired with a bare domain route)
      if (route.force_https && route.backend_addresses.length === 0 && !route.redirect_to) {
        return true;
      }
      return false;
    })();

    if (!isWwwRedirect) continue;

    // Find the bare domain primary route
    const bareRoutes = byHostname.get(bareDomain);
    if (!bareRoutes) continue;

    for (const primary of bareRoutes) {
      if (removedIndices.has(routes.indexOf(primary))) continue;
      if (primary.path_prefix !== route.path_prefix) continue;
      if (primary.backend_addresses.length === 0 && !primary.redirect_to) continue;

      // Merge: add www.X as alias, set redirect_hostname
      const wwwHost = route.hostname; // preserve original casing
      if (!primary.hostname_aliases.includes(wwwHost) && wwwHost.toLowerCase() !== primary.hostname.toLowerCase()) {
        primary.hostname_aliases.push(wwwHost);
        primary.importedFields.add('hostname_aliases');
      }
      // Also absorb any aliases from the www route
      for (const alias of route.hostname_aliases) {
        if (!primary.hostname_aliases.includes(alias) && alias.toLowerCase() !== primary.hostname.toLowerCase()) {
          primary.hostname_aliases.push(alias);
        }
      }
      primary.redirect_hostname = primary.hostname;
      primary.importedFields.add('redirect_hostname');

      removedIndices.add(i);
      break;
    }
  }

  // --- Pass 3: Merge non-www redirect routes into www routes (reverse direction) ---
  // A non-www route: hostname is X and has redirect_to pointing to www.X
  for (let i = 0; i < routes.length; i++) {
    if (removedIndices.has(i)) continue;
    const route = routes[i];
    const host = route.hostname.toLowerCase();

    if (host.startsWith('www.')) continue; // already handled in pass 2

    // Check if this route redirects to www.X
    if (!route.redirect_to) continue;
    const target = route.redirect_to.toLowerCase();
    const wwwDomain = `www.${host}`;
    const isNonWwwRedirect =
      target === `https://${wwwDomain}` ||
      target === `http://${wwwDomain}` ||
      target === wwwDomain;

    if (!isNonWwwRedirect) continue;

    // Find the www.X primary route
    const wwwRoutes = byHostname.get(wwwDomain);
    if (!wwwRoutes) continue;

    for (const primary of wwwRoutes) {
      if (removedIndices.has(routes.indexOf(primary))) continue;
      if (primary.path_prefix !== route.path_prefix) continue;
      if (primary.backend_addresses.length === 0 && !primary.redirect_to) continue;

      // Merge: add X as alias, set redirect_hostname to www.X
      const bareHost = route.hostname;
      if (!primary.hostname_aliases.includes(bareHost) && bareHost.toLowerCase() !== primary.hostname.toLowerCase()) {
        primary.hostname_aliases.push(bareHost);
        primary.importedFields.add('hostname_aliases');
      }
      for (const alias of route.hostname_aliases) {
        if (!primary.hostname_aliases.includes(alias) && alias.toLowerCase() !== primary.hostname.toLowerCase()) {
          primary.hostname_aliases.push(alias);
        }
      }
      primary.redirect_hostname = primary.hostname;
      primary.importedFields.add('redirect_hostname');

      removedIndices.add(i);
      break;
    }
  }

  return routes.filter((_, i) => !removedIndices.has(i));
}

/**
 * Resolve upstream references in a list of backend addresses.
 *
 * If an address matches an upstream name, replace it with
 * the upstream's server list.
 *
 * @param addresses - Backend addresses (may contain upstream names)
 * @param upstreams - Parsed upstream blocks
 * @returns Resolved address list
 */
function resolveBackendAddresses(addresses: string[], upstreams: NginxUpstream[]): string[] {
  const upstreamMap = new Map(upstreams.map(u => [u.name, u]));
  const resolved: string[] = [];
  for (const addr of addresses) {
    const upstream = upstreamMap.get(addr);
    if (upstream) {
      resolved.push(...upstream.servers);
    } else {
      resolved.push(addr);
    }
  }
  return resolved;
}

/**
 * Convert an Nginx location block into a PathRuleImport.
 *
 * Applies the location's directives to a temporary route, then detects
 * what differs from the parent route to produce a minimal path rule.
 *
 * @param location - The Nginx location block
 * @param parentRoute - The parent route (from server-level directives)
 * @param diagnostics - Diagnostic accumulator
 * @param upstreams - Parsed upstream blocks
 * @returns A path rule, or null if the location has no meaningful overrides
 */
function locationToPathRule(
  location: NginxLocation,
  parentRoute: LoricaRouteImport,
  diagnostics: NginxDiagnostic[],
  upstreams: NginxUpstream[],
): PathRuleImport | null {
  // Build a temporary route to apply directives and detect what changed
  const tempRoute = createDefaultRoute();
  // Do NOT copy parent backends - let applyDirective populate from scratch

  for (const dir of location.directives) {
    applyDirective(dir, tempRoute, diagnostics);
  }

  // Determine match type from location path
  const isExact = location.path.startsWith('= ');
  const cleanPath = isExact ? location.path.substring(2).trim() : location.path;

  const rule: PathRuleImport = {
    path: cleanPath || '/',
    match_type: isExact ? 'exact' : 'prefix',
  };

  // Detect what's different from parent route
  // Backend override: if proxy_pass in location points to a different upstream than parent
  if (tempRoute.importedFields.has('backend_addresses') && tempRoute.backend_addresses.length > 0) {
    const resolvedAddrs = resolveBackendAddresses(tempRoute.backend_addresses, upstreams);
    const parentAddrs = resolveBackendAddresses(parentRoute.backend_addresses, upstreams);
    if (JSON.stringify(resolvedAddrs) !== JSON.stringify(parentAddrs)) {
      rule.backend_addresses = resolvedAddrs;
    }
  }

  // Cache override
  if (tempRoute.importedFields.has('cache_enabled') || tempRoute.importedFields.has('cache_ttl_s')) {
    rule.cache_enabled = tempRoute.cache_enabled;
    if (tempRoute.cache_ttl_s > 0) rule.cache_ttl_s = tempRoute.cache_ttl_s;
  }

  // Response headers override
  if (tempRoute.importedFields.has('response_headers') && Object.keys(tempRoute.response_headers).length > 0) {
    rule.response_headers = tempRoute.response_headers;
  }

  // Rate limiting override
  if (tempRoute.importedFields.has('rate_limit_rps')) {
    rule.rate_limit_rps = tempRoute.rate_limit_rps ?? undefined;
  }
  if (tempRoute.importedFields.has('rate_limit_burst')) {
    rule.rate_limit_burst = tempRoute.rate_limit_burst ?? undefined;
  }

  // Check for return status (return 403, return 404, etc.)
  if (tempRoute.importedFields.has('return_status') && tempRoute.return_status != null) {
    rule.return_status = tempRoute.return_status;
  }

  // Check for redirects
  if (tempRoute.importedFields.has('force_https') && tempRoute.force_https) {
    rule.redirect_to = `https://${parentRoute.hostname}`;
    rule.return_status = 301;
  }
  if (tempRoute.importedFields.has('redirect_to') && tempRoute.redirect_to) {
    rule.redirect_to = tempRoute.redirect_to;
    rule.return_status = 301;
  }

  // Skip empty rules that have no meaningful overrides
  const hasOverride = rule.backend_addresses || rule.cache_enabled != null ||
    rule.response_headers || rule.rate_limit_rps != null ||
    rule.redirect_to || rule.return_status;

  return hasOverride ? rule : null;
}

/**
 * Convert a parsed Nginx config into Lorica route imports.
 *
 * Each server block produces one route. Non-root locations within
 * a server block become path rules on that route. Server-level
 * directives and root location directives are applied to the route.
 * Upstream references in proxy_pass are resolved to actual server addresses.
 *
 * @param result - Output from parseNginxConfig
 * @returns Array of Lorica route import objects
 */
export function convertToLoricaRoutes(result: NginxParseResult): LoricaRouteImport[] {
  const routes: LoricaRouteImport[] = [];
  const diagnostics = result.diagnostics;

  for (const server of result.servers) {
    // Skip server blocks listening on non-standard ports (Lorica serves 80/443 only)
    const hasNonStandardPort = server.listen.some((l) => {
      const portMatch = l.match(/(\d+)/);
      if (!portMatch) return false;
      const port = parseInt(portMatch[1], 10);
      return port !== 80 && port !== 443;
    });
    if (hasNonStandardPort) continue;

    const route = createDefaultRoute();

    // Apply server-level SSL flag
    if (server.ssl) {
      route.certificate_needed = true;
      route.importedFields.add('certificate_needed');
    }

    // Apply server-level directives
    for (const dir of server.directives) {
      applyDirective(dir, route, diagnostics);
    }

    if (server.locations.length === 0) {
      // No locations: simple route
      resolveUpstreams(route, result.upstreams);
      routes.push(route);
    } else {
      // Find root location "/" and non-root locations
      const rootLoc = server.locations.find(l => l.path === '/' || l.path === '');
      const subLocs = server.locations.filter(l => l !== rootLoc);

      // Apply root location directives to the route itself
      if (rootLoc) {
        for (const dir of rootLoc.directives) {
          applyDirective(dir, route, diagnostics);
        }
      }

      // Convert non-root locations to path rules
      for (const loc of subLocs) {
        const rule = locationToPathRule(loc, route, diagnostics, result.upstreams);
        if (rule) {
          route.path_rules.push(rule);
          route.importedFields.add('path_rules');
        }
      }

      resolveUpstreams(route, result.upstreams);
      routes.push(route);
    }
  }

  return mergeRelatedRoutes(routes);
}
