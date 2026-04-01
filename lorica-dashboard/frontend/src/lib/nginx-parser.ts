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
  rate_limit_rps: number | null;
  rate_limit_burst: number | null;
  cache_enabled: boolean;
  cache_ttl_s: number;
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
    const parts = v.split(/\s+/);
    const key = parts[0];
    const rest = parts.slice(1).join(' ').replace(/^"|"$/g, '');
    if (key) {
      r.response_headers[key] = rest;
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
    if (v.startsWith('301 https://') || v.startsWith('302 https://')) {
      r.force_https = true;
      r.importedFields.add('force_https');
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
      r.importedFields.add('cache_ttl_s');
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
    // Try to detect path prefix stripping: rewrite ^/prefix/(.*) /$1
    const match = v.match(/^\^?(\/.+?)\/(.*?)\s+\/\$1/);
    if (match) {
      r.strip_path_prefix = match[1];
      r.importedFields.add('strip_path_prefix');
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
 * brace-only segments separate.
 *
 * @param line - Cleaned config line
 * @returns Array of statement strings
 */
function splitStatements(line: string): string[] {
  const results: string[] = [];
  let current = '';
  for (const ch of line) {
    if (ch === ';') {
      const trimmed = current.trim();
      if (trimmed) results.push(trimmed);
      current = '';
    } else if (ch === '{' || ch === '}') {
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

    // Check if line is complete (has semicolon or brace)
    const hasSemicolon = lineToProcess.includes(';');
    const hasBrace = lineToProcess.includes('{') || lineToProcess.includes('}');
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
    rate_limit_rps: null,
    rate_limit_burst: null,
    cache_enabled: false,
    cache_ttl_s: 0,
    importedFields: new Set<string>(),
  };
}

/**
 * Apply a directive to a route using the DIRECTIVE_MAP.
 *
 * Unknown directives generate an info-level diagnostic.
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
 * Convert a parsed Nginx config into Lorica route imports.
 *
 * Each server+location combination produces one route. Server-level
 * directives are applied first, then location-level directives override.
 * Upstream references in proxy_pass are resolved to actual server addresses.
 *
 * @param result - Output from parseNginxConfig
 * @returns Array of Lorica route import objects
 */
export function convertToLoricaRoutes(result: NginxParseResult): LoricaRouteImport[] {
  const routes: LoricaRouteImport[] = [];
  const diagnostics = result.diagnostics;

  for (const server of result.servers) {
    if (server.locations.length === 0) {
      // Server with no locations: create a single route from server directives
      const route = createDefaultRoute();

      if (server.ssl) {
        route.certificate_needed = true;
        route.importedFields.add('certificate_needed');
      }

      for (const dir of server.directives) {
        applyDirective(dir, route, diagnostics);
      }

      resolveUpstreams(route, result.upstreams);
      routes.push(route);
    } else {
      // One route per location
      for (const location of server.locations) {
        const route = createDefaultRoute();
        route.path_prefix = location.path;
        route.importedFields.add('path_prefix');

        if (server.ssl) {
          route.certificate_needed = true;
          route.importedFields.add('certificate_needed');
        }

        // Apply server-level directives first
        for (const dir of server.directives) {
          applyDirective(dir, route, diagnostics);
        }

        // Apply location-level directives (override server-level)
        for (const dir of location.directives) {
          applyDirective(dir, route, diagnostics);
        }

        resolveUpstreams(route, result.upstreams);
        routes.push(route);
      }
    }
  }

  return routes;
}
