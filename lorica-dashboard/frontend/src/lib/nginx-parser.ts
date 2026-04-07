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
    if (key) {
      r.proxy_headers[key] = rest;
      r.importedFields.add('proxy_headers');
    }
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
      r.response_headers[key] = val;
      r.importedFields.add('response_headers');
      if (isSecurityHeader(key)) {
        r.security_headers = 'strict';
        r.importedFields.add('security_headers');
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

  ssl_certificate: (_v, r) => {
    r.certificate_needed = true;
    r.importedFields.add('certificate_needed');
  },

  ssl_certificate_key: (_v, r) => {
    r.certificate_needed = true;
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
          message: 'Conditional "if" block not supported. Verify behavior after import.',
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
 * Nginx directives that Lorica handles differently or that are not relevant.
 * These are silently ignored (no diagnostic) because they are well-known
 * Nginx directives, not typos or unknown config.
 */
const SILENTLY_IGNORED_DIRECTIVES = new Set([
  'listen',
  'http2',
  'ssl',
  'ssl_dhparam',
  'ssl_protocols',
  'ssl_ciphers',
  'ssl_prefer_server_ciphers',
  'ssl_session_cache',
  'ssl_session_timeout',
  'ssl_session_tickets',
  'ssl_stapling',
  'ssl_stapling_verify',
  'ssl_trusted_certificate',
  'proxy_http_version',
  'proxy_buffering',
  'proxy_buffer_size',
  'proxy_buffers',
  'proxy_busy_buffers_size',
  'keepalive',
  'keepalive_timeout',
  'keepalive_requests',
  'access_log',
  'error_log',
  'gzip',
  'gzip_types',
  'gzip_vary',
  'gzip_proxied',
  'gzip_comp_level',
  'gzip_min_length',
  'sendfile',
  'tcp_nopush',
  'tcp_nodelay',
  'resolver',
  'charset',
  'server_tokens',
  'root',
  'index',
  'try_files',
  'error_page',
  'expires',
  'etag',
  'if_modified_since',
]);

/**
 * Apply a directive to a route using the DIRECTIVE_MAP.
 *
 * Known-but-irrelevant directives are silently skipped.
 * Truly unknown directives generate an info-level diagnostic.
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
  } else if (SILENTLY_IGNORED_DIRECTIVES.has(directive.name)) {
    // Known Nginx directive - Lorica handles this differently, skip silently
  } else {
    diagnostics.push({
      level: 'info',
      line: directive.line,
      message: `Skipped unknown directive "${directive.name}".`,
      directive: directive.name,
    });
  }
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
