/**
 * The Capture page's pure logic (Story 10.2 AC #5): the create/edit
 * form's state, the refusal that keeps an unbounded rule from being
 * submitted by accident, the request body it becomes, and the two
 * figures every rule row shows (remaining budget, time to expiry).
 *
 * Kept out of the components so each rule here has a unit test that
 * does not need a DOM. The server validates the same rules again
 * (`CaptureRule::validate`); the form's job is to make the mistake
 * hard, not to be the only guard.
 */

import type {
  CaptureRuleRequest,
  CaptureRuleResponse,
  CaptureStatusMatch,
} from './api';

/** Server-side caps, restated so the form can refuse before the round trip. */
export const CAPTURE_BODY_MAX_BYTES_CAP = 4 * 1024 * 1024;
export const CAPTURE_MAX_CAPTURES_CAP = 10_000;
export const CAPTURE_RATE_PER_MINUTE_CAP = 10_000;
export const CAPTURE_TTL_SECONDS_CAP = 7 * 24 * 60 * 60;

/** Every field of the form, as the inputs bind them (strings for free text). */
export interface CaptureFormState {
  name: string;
  routeId: string;
  enabled: boolean;
  /** One CIDR or address per line. */
  sourceCidrs: string;
  /** Comma or whitespace separated, uppercased on submit. */
  methods: string;
  pathPrefix: string;
  pathRegex: string;
  statusServerError: boolean;
  statusClientError: boolean;
  statusClientAborted: boolean;
  /** Comma separated exact codes, e.g. `502, 504`. */
  statusExact: string;
  /** Empty string when unset. */
  minLatencyMs: string;
  upstreamError: boolean;
  /** The explicit acknowledgement that every request on the route is recorded. */
  always: boolean;
  requestBody: boolean;
  responseBody: boolean;
  requestBodyMaxBytes: number;
  responseBodyMaxBytes: number;
  maxCaptures: number;
  ratePerMinute: number;
  ttlSeconds: number;
  outputDir: string;
  /** Empty string when unset. */
  maxDirBytes: string;
  /** One header name per line. */
  redactHeaders: string;
  /** One query-parameter name per line. */
  redactQuery: string;
}

/** The form as it opens for a new rule: the server's defaults. */
export function emptyCaptureForm(routeId = ''): CaptureFormState {
  return {
    name: '',
    routeId,
    enabled: true,
    sourceCidrs: '',
    methods: '',
    pathPrefix: '',
    pathRegex: '',
    statusServerError: true,
    statusClientError: false,
    statusClientAborted: false,
    statusExact: '',
    minLatencyMs: '',
    upstreamError: false,
    always: false,
    requestBody: true,
    responseBody: true,
    requestBodyMaxBytes: 64 * 1024,
    responseBodyMaxBytes: 64 * 1024,
    maxCaptures: 100,
    ratePerMinute: 10,
    ttlSeconds: 3600,
    outputDir: '',
    maxDirBytes: '',
    redactHeaders: '',
    redactQuery: '',
  };
}

/** The form as it opens on an existing rule. */
export function captureFormFromRule(rule: CaptureRuleResponse): CaptureFormState {
  const exact: number[] = [];
  let serverError = false;
  let clientError = false;
  let clientAborted = false;
  for (const s of rule.emit.status) {
    if (s === 'server_error') serverError = true;
    else if (s === 'client_error') clientError = true;
    else if (s === 'client_aborted') clientAborted = true;
    else exact.push(s.exact);
  }
  return {
    name: rule.name,
    routeId: rule.route_id,
    enabled: rule.enabled,
    sourceCidrs: rule.match.source_cidrs.join('\n'),
    methods: rule.match.methods.join(', '),
    pathPrefix: rule.match.path_prefix ?? '',
    pathRegex: rule.match.path_regex ?? '',
    statusServerError: serverError,
    statusClientError: clientError,
    statusClientAborted: clientAborted,
    statusExact: exact.join(', '),
    minLatencyMs: rule.emit.min_latency_ms === null ? '' : String(rule.emit.min_latency_ms),
    upstreamError: rule.emit.upstream_error,
    always: rule.emit.always,
    requestBody: rule.capture.request_body,
    responseBody: rule.capture.response_body,
    requestBodyMaxBytes: rule.capture.request_body_max_bytes,
    responseBodyMaxBytes: rule.capture.response_body_max_bytes,
    maxCaptures: rule.limits.max_captures,
    ratePerMinute: rule.limits.rate_per_minute,
    ttlSeconds: rule.limits.ttl_seconds,
    outputDir: rule.output.dir ?? '',
    maxDirBytes: rule.output.max_dir_bytes === null ? '' : String(rule.output.max_dir_bytes),
    redactHeaders: rule.redact.headers.join('\n'),
    redactQuery: rule.redact.query.join('\n'),
  };
}

function lines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function tokens(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * The exact status codes typed into the form. `null` when one token
 * is not a status code, so the caller can name the field.
 */
export function parseExactStatuses(text: string): number[] | null {
  const codes: number[] = [];
  for (const token of tokens(text)) {
    if (!/^\d{3}$/.test(token)) return null;
    const code = Number(token);
    if (code < 100 || code > 599) return null;
    codes.push(code);
  }
  return codes;
}

/**
 * Whether the form carries at least one response-side condition. A
 * rule without one and without the `always` acknowledgement is the
 * unbounded rule the form exists to refuse.
 */
export function hasEmitCondition(f: CaptureFormState): boolean {
  return (
    f.statusServerError ||
    f.statusClientError ||
    f.statusClientAborted ||
    tokens(f.statusExact).length > 0 ||
    f.minLatencyMs.trim() !== '' ||
    f.upstreamError
  );
}

/**
 * The first reason the form must not be submitted, or `''` when it
 * may. The order is the order an operator fills the form in.
 */
export function validateCaptureForm(f: CaptureFormState): string {
  if (f.name.trim() === '') return 'Name is required';
  if (f.routeId === '') return 'A capture rule records one route: pick it';
  const conditioned = hasEmitCondition(f);
  if (!conditioned && !f.always) {
    return 'Add a status, latency or upstream-error condition, or acknowledge that every request on the route will be recorded';
  }
  if (conditioned && f.always) {
    return '"Record every request" cannot be combined with a status, latency or upstream-error condition';
  }
  if (parseExactStatuses(f.statusExact) === null) {
    return 'Exact statuses must be three-digit codes between 100 and 599';
  }
  if (f.minLatencyMs.trim() !== '' && !(Number(f.minLatencyMs) >= 0)) {
    return 'Minimum latency must be a number of milliseconds';
  }
  if (f.pathPrefix.trim() !== '' && !f.pathPrefix.startsWith('/')) {
    return 'Path prefix must start with /';
  }
  for (const [value, cap, label] of [
    [f.requestBodyMaxBytes, CAPTURE_BODY_MAX_BYTES_CAP, 'Request body cap'],
    [f.responseBodyMaxBytes, CAPTURE_BODY_MAX_BYTES_CAP, 'Response body cap'],
    [f.maxCaptures, CAPTURE_MAX_CAPTURES_CAP, 'Max captures'],
    [f.ratePerMinute, CAPTURE_RATE_PER_MINUTE_CAP, 'Rate per minute'],
    [f.ttlSeconds, CAPTURE_TTL_SECONDS_CAP, 'TTL'],
  ] as const) {
    if (!Number.isInteger(value) || value < 1 || value > cap) {
      return `${label} must be between 1 and ${cap}`;
    }
  }
  if (f.outputDir.trim() !== '' && !f.outputDir.startsWith('/')) {
    return 'Output directory must be an absolute path';
  }
  if (f.maxDirBytes.trim() !== '' && !(Number(f.maxDirBytes) >= 1)) {
    return 'Directory size budget must be a positive number of bytes';
  }
  return '';
}

/** The request body a valid form becomes. */
export function toCaptureRuleRequest(f: CaptureFormState): CaptureRuleRequest {
  const status: CaptureStatusMatch[] = [];
  if (f.statusServerError) status.push('server_error');
  if (f.statusClientError) status.push('client_error');
  if (f.statusClientAborted) status.push('client_aborted');
  for (const code of parseExactStatuses(f.statusExact) ?? []) status.push({ exact: code });
  const minLatency = f.minLatencyMs.trim() === '' ? null : Number(f.minLatencyMs);
  const maxDir = f.maxDirBytes.trim() === '' ? null : Number(f.maxDirBytes);
  return {
    name: f.name.trim(),
    route_id: f.routeId,
    enabled: f.enabled,
    match: {
      source_cidrs: lines(f.sourceCidrs),
      methods: tokens(f.methods).map((m) => m.toUpperCase()),
      path_prefix: f.pathPrefix.trim() === '' ? null : f.pathPrefix.trim(),
      path_regex: f.pathRegex.trim() === '' ? null : f.pathRegex.trim(),
      headers: [],
    },
    emit: {
      always: f.always,
      status,
      min_latency_ms: minLatency,
      upstream_error: f.upstreamError,
    },
    capture: {
      request_body: f.requestBody,
      response_body: f.responseBody,
      request_body_max_bytes: f.requestBodyMaxBytes,
      response_body_max_bytes: f.responseBodyMaxBytes,
    },
    limits: {
      max_captures: f.maxCaptures,
      rate_per_minute: f.ratePerMinute,
      ttl_seconds: f.ttlSeconds,
    },
    output: {
      dir: f.outputDir.trim() === '' ? null : f.outputDir.trim(),
      max_dir_bytes: maxDir,
    },
    redact: {
      headers: lines(f.redactHeaders),
      query: lines(f.redactQuery),
    },
  };
}

/**
 * The `expires_at` a TTL produces, anchored the way the server anchors
 * it: on the rule's creation, not on the edit. For a new rule the
 * anchor is now.
 */
export function expiresAtFrom(anchor: Date, ttlSeconds: number): Date {
  const ttl = Number.isFinite(ttlSeconds) ? Math.max(0, Math.floor(ttlSeconds)) : 0;
  return new Date(anchor.getTime() + ttl * 1000);
}

/** Captures the rule may still emit before it disables itself. */
export function remainingBudget(rule: Pick<CaptureRuleResponse, 'limits' | 'captures_emitted'>): number {
  return Math.max(0, rule.limits.max_captures - rule.captures_emitted);
}

/**
 * A short "in 42m" / "in 3d 2h" / "expired" for a rule row. Seconds
 * are shown only under a minute, so the column does not tick.
 */
export function formatTimeUntil(target: Date, now: Date): string {
  const seconds = Math.floor((target.getTime() - now.getTime()) / 1000);
  if (!Number.isFinite(seconds)) return '-';
  if (seconds <= 0) return 'expired';
  if (seconds < 60) return `in ${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `in ${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `in ${hours}h ${minutes % 60}m`;
  const days = Math.floor(hours / 24);
  return `in ${days}d ${hours % 24}h`;
}

/** Whether a rule's clock has run out, whatever its `enabled` flag says. */
export function isExpired(rule: Pick<CaptureRuleResponse, 'expires_at'>, now: Date): boolean {
  return new Date(rule.expires_at).getTime() <= now.getTime();
}

/** One line describing when a rule emits, for the rule table. */
export function describeEmit(emit: CaptureRuleResponse['emit']): string {
  if (emit.always) return 'every request';
  const parts: string[] = [];
  const status = emit.status.map((s) =>
    s === 'server_error' ? '5xx' : s === 'client_error' ? '4xx' : s === 'client_aborted' ? '499' : String(s.exact),
  );
  if (status.length > 0) parts.push(`status ${status.join(', ')}`);
  if (emit.min_latency_ms !== null) parts.push(`latency >= ${emit.min_latency_ms} ms`);
  if (emit.upstream_error) parts.push('upstream error');
  return parts.join(' or ');
}
