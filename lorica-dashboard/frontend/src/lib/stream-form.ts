/**
 * The stream form's rules (Story 12.10 D-b): which field applies to
 * which stream, which tab holds it, and the body a save sends.
 *
 * The form refuses nothing itself. No range is copied here: an empty
 * field means the server default, and the server's refusal is shown on
 * the tab holding the field it names (`fieldTab`). What it gives up: a
 * range error appears on save, not on keystroke.
 */

import type {
  CreateStreamRequest,
  GeoIpMode,
  StreamLoadBalancing,
  StreamMatchRule,
  StreamProtocol,
  StreamProxyProtocol,
  StreamResponse,
  StreamTlsMode,
  StreamUdpSettings,
  StreamUdpSettingsInput,
  StreamUpstreamServerName,
  StreamWritableFields,
  UpdateStreamRequest,
} from './api';

export type StreamField = keyof StreamWritableFields;

export type StreamTab = 'general' | 'backends' | 'tls' | 'connection' | 'udp' | 'protection';

export const STREAM_TABS: { id: StreamTab; label: string }[] = [
  { id: 'general', label: 'General' },
  { id: 'backends', label: 'Backends' },
  { id: 'tls', label: 'TLS' },
  { id: 'connection', label: 'Connection' },
  { id: 'udp', label: 'UDP' },
  { id: 'protection', label: 'Protection' },
];

/**
 * The tab holding each writable field, in the order the tab shows them
 * (`scalarsOn`). A field added to the view is a type error here until
 * placed.
 */
export const FIELD_TAB: Record<StreamField, StreamTab> = {
  name: 'general',
  group_name: 'general',
  protocol: 'general',
  enabled: 'general',
  listen_address: 'general',
  port_first: 'general',
  port_last: 'general',
  node_selector: 'general',
  backend_ids: 'backends',
  backup_backend_ids: 'backends',
  backend_max_active: 'backends',
  tls_mode: 'tls',
  match_rules: 'tls',
  clienthello_timeout_ms: 'tls',
  no_sni_acknowledged: 'tls',
  tls_terminate: 'tls',
  upstream_tls: 'tls',
  load_balancing: 'connection',
  connect_timeout_ms: 'connection',
  idle_timeout_s: 'connection',
  total_timeout_s: 'connection',
  max_connect_attempts: 'connection',
  backend_keepalive: 'connection',
  backend_keepalive_idle_s: 'connection',
  close_on_backend_down: 'connection',
  max_connections: 'connection',
  upload_rate_bps: 'connection',
  download_rate_bps: 'connection',
  proxy_protocol_send: 'connection',
  proxy_protocol_accept: 'connection',
  proxy_protocol_trusted_cidrs: 'connection',
  source_addresses: 'connection',
  allow_local_backend: 'connection',
  udp: 'udp',
  source_allow_cidrs: 'protection',
  source_deny_cidrs: 'protection',
  geoip: 'protection',
  source_max_connections: 'protection',
  max_pending_connections: 'protection',
  source_open_rate: 'protection',
  open_rate: 'protection',
};

const ALWAYS: readonly StreamField[] = [
  'name',
  'group_name',
  'protocol',
  'enabled',
  'listen_address',
  'port_first',
  'port_last',
  'node_selector',
  'source_allow_cidrs',
  'source_deny_cidrs',
  'geoip',
  'source_open_rate',
  'open_rate',
];

/** The settings of Story 12.3 a UDP stream gives a meaning to (Story 12.5 D-l); the others must hold their default there. */
const LIFTED_ON_UDP: readonly StreamField[] = [
  'load_balancing',
  'idle_timeout_s',
  'total_timeout_s',
  'close_on_backend_down',
  'allow_local_backend',
  'proxy_protocol_send',
  'source_addresses',
];

/** Every Connection field, TCP's whole set. */
const CONNECTION: readonly StreamField[] = (Object.keys(FIELD_TAB) as StreamField[]).filter(
  (field) => FIELD_TAB[field] === 'connection',
);

/** Stream-level links, which a TLS stream carries per rule instead. */
const STREAM_LINKS: readonly StreamField[] = ['backend_ids', 'backup_backend_ids', 'backend_max_active'];

/**
 * The fields a stream of `protocol` and `tlsMode` takes: the ones the
 * form shows, and the only ones it sends. The server refuses a field
 * that does not apply rather than ignoring it, so a field not shown is
 * never sent.
 */
export function fieldsFor(protocol: StreamProtocol, tlsMode: StreamTlsMode): ReadonlySet<StreamField> {
  const fields = new Set<StreamField>(ALWAYS);
  if (protocol === 'udp') {
    for (const f of [...LIFTED_ON_UDP, ...STREAM_LINKS, 'udp' as const]) fields.add(f);
    return fields;
  }
  for (const f of [...CONNECTION, 'source_max_connections', 'max_pending_connections', 'tls_mode'] as const) {
    fields.add(f);
  }
  if (tlsMode === 'none') {
    for (const f of [...STREAM_LINKS, 'upstream_tls' as const]) fields.add(f);
  } else {
    for (const f of ['match_rules', 'no_sni_acknowledged', 'clienthello_timeout_ms'] as const) fields.add(f);
    if (tlsMode === 'terminate') {
      fields.add('tls_terminate');
      fields.add('upstream_tls');
    }
  }
  return fields;
}

/** The tabs a stream of `protocol` and `tlsMode` shows: those holding at least one of its fields. */
export function tabsFor(protocol: StreamProtocol, tlsMode: StreamTlsMode): StreamTab[] {
  const fields = fieldsFor(protocol, tlsMode);
  const shown = new Set([...fields].map((f) => FIELD_TAB[f]));
  // A TLS stream lists its backends per rule, which the Backends tab
  // edits too.
  if (fields.has('match_rules')) shown.add('backends');
  return STREAM_TABS.map((t) => t.id).filter((id) => shown.has(id));
}

const FIELDS_LONGEST_FIRST = (Object.keys(FIELD_TAB) as StreamField[]).sort((a, b) => b.length - a.length);

/**
 * The tab holding the field a server refusal names, so the message is
 * shown where the field is. A field is named whole (`max_connections`
 * is not read inside `source_max_connections`); a rule's links are on
 * the Backends tab, the rest of a rule on the TLS one. `general` when no
 * field is named (a port conflict, the fd budget).
 */
export function fieldTab(message: string): StreamTab {
  for (const field of FIELDS_LONGEST_FIRST) {
    const named = new RegExp(`(^|[^a-z_])${field}([^a-z_]|$)`).test(message);
    if (!named) continue;
    if (field === 'match_rules' && /backend/.test(message)) return 'backends';
    return FIELD_TAB[field];
  }
  return 'general';
}

// --- Scalar fields: how each is edited ---

/**
 * `text`: a string. `int`: a number the server requires, empty for its
 * default. `optional`: a nullable number, empty for `null` (no limit, or
 * the default the field documents). `bool`: on, off, or on a create the
 * server default. `lines`: a list, one entry per line. `choice`: one of
 * `choices`.
 */
export type ScalarKind = 'text' | 'int' | 'optional' | 'bool' | 'lines' | 'choice';

export interface ScalarSpec {
  label: string;
  kind: ScalarKind;
  /** A cap or rate that applies on each node binding the stream (12.6 D-k). */
  perNode?: boolean;
  /** One line next to the control: what the field opens or bounds. */
  help?: string;
  /** What an empty input means, as the placeholder. */
  empty?: string;
}

/** The fields edited as one control, every one of them, keyed so a missing one is a type error. */
export type ScalarField = Exclude<
  StreamField,
  'backend_ids' | 'backup_backend_ids' | 'backend_max_active' | 'match_rules' | 'tls_terminate' | 'upstream_tls' | 'geoip' | 'udp'
>;

export const SCALAR_SPECS: Record<ScalarField, ScalarSpec> = {
  name: { label: 'Name', kind: 'text', help: 'Lowercase letters, digits, - and _; unique in the fleet.' },
  group_name: { label: 'Group', kind: 'text' },
  protocol: { label: 'Protocol', kind: 'choice' },
  enabled: { label: 'Enabled', kind: 'bool', help: 'A disabled stream is bound on no node and keeps its ports reserved.' },
  listen_address: { label: 'Listen address', kind: 'text', help: '0.0.0.0, or :: for dual-stack; any other address binds that one only.' },
  port_first: { label: 'Port (first)', kind: 'int' },
  port_last: {
    label: 'Last port of a range',
    kind: 'optional',
    empty: 'single port',
    help: 'A range forwards listen port N to backend port N, so its backends carry no port.',
  },
  node_selector: { label: 'Node selector', kind: 'lines', empty: 'every node', help: 'Node names, one per line; empty binds the stream on every node.' },
  tls_mode: { label: 'TLS mode', kind: 'choice' },
  no_sni_acknowledged: {
    label: 'Acknowledge clients without SNI',
    kind: 'bool',
    help: 'A no-SNI rule admits clients that name no server; without a source allowlist the server asks for this acknowledgement.',
  },
  clienthello_timeout_ms: { label: 'ClientHello timeout (ms)', kind: 'optional', empty: 'server default' },
  load_balancing: { label: 'Load balancing', kind: 'choice' },
  connect_timeout_ms: { label: 'Connect timeout (ms)', kind: 'int', empty: 'server default' },
  idle_timeout_s: { label: 'Idle timeout (s)', kind: 'int', empty: 'server default' },
  total_timeout_s: { label: 'Total timeout (s)', kind: 'optional', empty: 'no limit' },
  max_connect_attempts: { label: 'Connect attempts', kind: 'int', empty: 'server default' },
  backend_keepalive: { label: 'TCP keepalive to backends', kind: 'bool' },
  backend_keepalive_idle_s: { label: 'Keepalive idle (s)', kind: 'int', empty: 'server default' },
  close_on_backend_down: { label: 'Close connections to a backend that goes down', kind: 'bool' },
  proxy_protocol_send: { label: 'Send PROXY protocol', kind: 'choice' },
  proxy_protocol_accept: {
    label: 'Accept PROXY protocol',
    kind: 'bool',
    help: 'Trusts the client address a peer in the trusted list writes: a wrong list lets that peer pose as any client.',
  },
  proxy_protocol_trusted_cidrs: { label: 'Trusted PROXY peers', kind: 'lines', help: 'CIDRs or addresses, one per line.' },
  source_addresses: { label: 'Source addresses', kind: 'lines', empty: 'kernel choice', help: 'Local addresses backend connections leave from, in turn; one per line.' },
  allow_local_backend: {
    label: 'Allow a local backend',
    kind: 'bool',
    help: 'Lets the stream reach a local address of the node (loopback, link-local, localhost or its own), never a reserved port.',
  },
  upload_rate_bps: { label: 'Upload rate (bytes/s per connection)', kind: 'optional', empty: 'no limit' },
  download_rate_bps: { label: 'Download rate (bytes/s per connection)', kind: 'optional', empty: 'no limit' },
  max_connections: { label: 'Max connections', kind: 'int', perNode: true, empty: 'server default' },
  source_allow_cidrs: { label: 'Source allowlist', kind: 'lines', help: 'CIDRs or addresses, one per line; when set, every other source is refused.' },
  source_deny_cidrs: { label: 'Source denylist', kind: 'lines', help: 'CIDRs or addresses, one per line; a deny entry always wins.' },
  source_max_connections: { label: 'Max connections per source', kind: 'optional', perNode: true, empty: 'bounded by max connections' },
  max_pending_connections: { label: 'Max pending connections', kind: 'int', perNode: true, empty: 'server default' },
  source_open_rate: { label: 'Openings per second per source', kind: 'optional', perNode: true, empty: 'no limit' },
  open_rate: { label: 'Openings per second', kind: 'optional', perNode: true, empty: 'no limit' },
};

export type UdpField = keyof StreamUdpSettings;

export const UDP_SPECS: Record<UdpField, ScalarSpec> = {
  max_sessions: { label: 'Max sessions', kind: 'int', perNode: true, empty: 'server default', help: "The stream's share of the node's session ceiling." },
  source_session_cap: { label: 'Sessions per source', kind: 'optional', perNode: true, empty: 'server default' },
  requests_per_session: { label: 'Requests per session', kind: 'int', empty: 'server default' },
  responses_per_request: { label: 'Responses per request', kind: 'int', empty: 'server default', help: '0 for a one-way protocol (syslog).' },
  response_bytes_ratio: { label: 'Response bytes per request byte', kind: 'int', empty: 'server default' },
  unbounded_responses: {
    label: 'Unbounded responses',
    kind: 'bool',
    help: 'Lifts both response bounds: a backend may send any amount back, which a spoofed source can turn into reflection.',
  },
  source_datagram_rate: { label: 'Datagrams per second per source', kind: 'int', perNode: true, empty: 'server default' },
  source_byte_rate: { label: 'Bytes per second per source', kind: 'int', perNode: true, empty: 'server default' },
  max_datagram_bytes: { label: 'Max datagram bytes', kind: 'int', empty: 'server default' },
};

/**
 * The scalar fields `tab` holds, in display order: what the tab renders
 * as one control each, next to the controls it builds by hand.
 */
export function scalarsOn(tab: StreamTab): ScalarField[] {
  return (Object.keys(FIELD_TAB) as StreamField[]).filter(
    (field): field is ScalarField => FIELD_TAB[field] === tab && field in SCALAR_SPECS,
  );
}

/** The label a control shows: every cap says it applies per node (12.6 D-k). */
export function labelOf(spec: ScalarSpec): string {
  return spec.perNode ? `${spec.label} (per node)` : spec.label;
}

/** The choices of each `choice` field, the stream's protocol narrowing two of them (12.5 D-l). */
const LOAD_BALANCING: Record<StreamLoadBalancing, string> = {
  round_robin: 'Round robin',
  consistent_hash: 'Consistent hash (client address)',
  random: 'Random',
  peak_ewma: 'Peak EWMA (connect latency)',
  least_conn: 'Least connections',
};

const PROXY_SEND: Record<StreamProxyProtocol, string> = { off: 'Off', v1: 'v1', v2: 'v2' };
const PROTOCOLS: Record<StreamProtocol, string> = { tcp: 'TCP', udp: 'UDP' };
const TLS_MODES: Record<StreamTlsMode, string> = {
  none: 'None (forward bytes)',
  passthrough: 'Passthrough (route on SNI)',
  terminate: 'Terminate',
};

export function choicesOf(field: ScalarField, protocol: StreamProtocol): { value: string; label: string }[] {
  const pairs = (record: Record<string, string>) => Object.entries(record).map(([value, label]) => ({ value, label }));
  switch (field) {
    case 'protocol':
      return pairs(PROTOCOLS);
    case 'tls_mode':
      return pairs(TLS_MODES);
    case 'load_balancing':
      // Peak EWMA weighs connect latency, which a UDP session has not.
      return pairs(LOAD_BALANCING).filter((c) => protocol === 'tcp' || c.value !== 'peak_ewma');
    case 'proxy_protocol_send':
      // A UDP stream sends v2 per datagram; v1 is text over a connection.
      return pairs(PROXY_SEND).filter((c) => protocol === 'tcp' || c.value !== 'v1');
    default:
      return [];
  }
}

// --- The draft the drawer edits ---

/** `null` is an empty input: the server default, no limit, or on a create a boolean left to the server. */
export type DraftValue = string | number | boolean | null;

export interface RuleDraft {
  name: string;
  kind: 'tls' | 'no_sni';
  /** One per line. */
  server_names: string;
  alpn: string;
  backend_ids: string[];
  backup_backend_ids: string[];
  backend_max_active: Record<string, number | null>;
}

export interface StreamDraft {
  scalars: Record<ScalarField, DraftValue>;
  backend_ids: string[];
  backup_backend_ids: string[];
  backend_max_active: Record<string, number | null>;
  rules: RuleDraft[];
  udp: Record<UdpField, DraftValue>;
  /** `requests_per_session` is `null` for no bound, which an empty input cannot say: it means the default. */
  udpRequestsUnbounded: boolean;
  /** `''` for no country list. */
  geoipMode: GeoIpMode | '';
  /** Comma-separated codes, the country picker's shape. */
  geoipCountries: string;
  certificateIds: string[];
  clientAuth: boolean;
  clientAuthCaPem: string;
  clientAuthRequired: boolean;
  clientAuthOrganizations: string;
  upstreamTls: boolean;
  upstreamServerName: StreamUpstreamServerName['mode'] | '';
  upstreamFixedName: string;
  upstreamCaPem: string;
  upstreamSkipVerify: boolean;
  upstreamClientCertificateId: string;
  upstreamAlpn: string;
}

const lines = (list: readonly string[]) => list.join('\n');

function emptyScalars(): Record<ScalarField, DraftValue> {
  const scalars = {} as Record<ScalarField, DraftValue>;
  for (const field of Object.keys(SCALAR_SPECS) as ScalarField[]) {
    scalars[field] = SCALAR_SPECS[field].kind === 'lines' || SCALAR_SPECS[field].kind === 'text' ? '' : null;
  }
  return scalars;
}

function emptyUdp(): Record<UdpField, DraftValue> {
  const udp = {} as Record<UdpField, DraftValue>;
  for (const field of Object.keys(UDP_SPECS) as UdpField[]) udp[field] = null;
  return udp;
}

/**
 * A create's draft: a TCP stream on every address, nothing else set, so
 * every field the operator leaves alone takes the server default.
 */
export function newDraft(): StreamDraft {
  const scalars = emptyScalars();
  scalars.protocol = 'tcp';
  scalars.listen_address = '0.0.0.0';
  return {
    scalars,
    backend_ids: [],
    backup_backend_ids: [],
    backend_max_active: {},
    rules: [],
    udp: emptyUdp(),
    udpRequestsUnbounded: false,
    geoipMode: '',
    geoipCountries: '',
    certificateIds: [],
    clientAuth: false,
    clientAuthCaPem: '',
    clientAuthRequired: false,
    clientAuthOrganizations: '',
    upstreamTls: false,
    upstreamServerName: '',
    upstreamFixedName: '',
    upstreamCaPem: '',
    upstreamSkipVerify: false,
    upstreamClientCertificateId: '',
    upstreamAlpn: '',
  };
}

export function emptyRule(): RuleDraft {
  return { name: '', kind: 'tls', server_names: '', alpn: '', backend_ids: [], backup_backend_ids: [], backend_max_active: {} };
}

/** An edit's draft: every field as stored. */
export function draftOf(stream: StreamResponse): StreamDraft {
  const scalars = emptyScalars();
  for (const field of Object.keys(SCALAR_SPECS) as ScalarField[]) {
    const value = stream[field];
    scalars[field] = Array.isArray(value) ? lines(value) : value;
  }
  // A single port is stored as last = first; the form shows it empty.
  if (stream.port_last === stream.port_first) scalars.port_last = null;
  const udp = emptyUdp();
  if (stream.udp) {
    for (const field of Object.keys(UDP_SPECS) as UdpField[]) udp[field] = stream.udp[field];
  }
  const upstream = stream.upstream_tls;
  const auth = stream.tls_terminate?.client_auth ?? null;
  return {
    scalars,
    backend_ids: [...stream.backend_ids],
    backup_backend_ids: [...stream.backup_backend_ids],
    backend_max_active: { ...stream.backend_max_active },
    rules: stream.match_rules.map((rule) => ({
      name: rule.name,
      kind: rule.matcher.kind,
      server_names: rule.matcher.kind === 'tls' ? lines(rule.matcher.server_names) : '',
      alpn: lines(rule.matcher.alpn ?? []),
      backend_ids: [...(rule.backend_ids ?? [])],
      backup_backend_ids: [...(rule.backup_backend_ids ?? [])],
      backend_max_active: { ...(rule.backend_max_active ?? {}) },
    })),
    udp,
    udpRequestsUnbounded: stream.udp !== null && stream.udp.requests_per_session === null,
    geoipMode: stream.geoip?.mode ?? '',
    geoipCountries: (stream.geoip?.countries ?? []).join(','),
    certificateIds: [...(stream.tls_terminate?.certificate_ids ?? [])],
    clientAuth: auth !== null,
    clientAuthCaPem: auth?.ca_cert_pem ?? '',
    clientAuthRequired: auth?.required ?? false,
    clientAuthOrganizations: lines(auth?.allowed_organizations ?? []),
    upstreamTls: upstream !== null,
    upstreamServerName: upstream?.server_name?.mode ?? '',
    upstreamFixedName: upstream?.server_name?.mode === 'fixed' ? upstream.server_name.name : '',
    upstreamCaPem: upstream?.ca_cert_pem ?? '',
    upstreamSkipVerify: upstream?.skip_verify ?? false,
    upstreamClientCertificateId: upstream?.client_certificate_id ?? '',
    upstreamAlpn: lines(upstream?.alpn ?? []),
  };
}

/** The protocol and TLS mode a draft is for; TLS is TCP only. */
export function shapeOf(draft: StreamDraft): { protocol: StreamProtocol; tlsMode: StreamTlsMode } {
  const protocol = draft.scalars.protocol === 'udp' ? 'udp' : 'tcp';
  const mode = draft.scalars.tls_mode;
  const tlsMode: StreamTlsMode = protocol === 'tcp' && (mode === 'passthrough' || mode === 'terminate') ? mode : 'none';
  return { protocol, tlsMode };
}

function splitLines(value: DraftValue | string): string[] {
  return String(value ?? '')
    .split('\n')
    .map((s) => s.trim())
    .filter((s) => s !== '');
}

function caps(record: Record<string, number | null>, linked: readonly string[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const id of linked) {
    const cap = record[id];
    if (typeof cap === 'number') out[id] = cap;
  }
  return out;
}

function ruleOf(rule: RuleDraft): StreamMatchRule {
  const alpn = splitLines(rule.alpn);
  const linked = [...rule.backend_ids, ...rule.backup_backend_ids];
  return {
    name: rule.name.trim(),
    matcher:
      rule.kind === 'tls'
        ? { kind: 'tls', server_names: splitLines(rule.server_names), alpn }
        : { kind: 'no_sni', alpn },
    backend_ids: rule.backend_ids,
    backup_backend_ids: rule.backup_backend_ids,
    backend_max_active: caps(rule.backend_max_active, linked),
  };
}

function udpOf(draft: StreamDraft): StreamUdpSettingsInput {
  const out: Record<string, number | boolean | null> = {};
  for (const field of Object.keys(UDP_SPECS) as UdpField[]) {
    const value = draft.udp[field];
    if (field === 'requests_per_session' && draft.udpRequestsUnbounded) {
      out[field] = null;
    } else if (value !== null && value !== '') {
      out[field] = value as number | boolean;
    }
  }
  return out as StreamUdpSettingsInput;
}

function scalarOf(field: ScalarField, value: DraftValue, mode: 'create' | 'edit'): { send: boolean; value?: unknown } {
  const spec = SCALAR_SPECS[field];
  switch (spec.kind) {
    case 'text':
      return { send: mode === 'edit' || String(value ?? '').trim() !== '', value: String(value ?? '').trim() };
    case 'lines': {
      const list = splitLines(value);
      return { send: mode === 'edit' || list.length > 0, value: list };
    }
    case 'int':
    case 'bool':
    case 'choice':
      // Empty: the server default on a create, the stored value on an edit.
      return value === null || value === '' ? { send: false } : { send: true, value };
    case 'optional':
      // Empty is `null`, which the field documents (no limit, or its default).
      return value === null || value === '' ? { send: mode === 'edit', value: null } : { send: true, value };
  }
}

/**
 * The body a save sends: only the fields `fieldsFor` the draft's shape
 * takes. On an edit, every one of them with its value, except a
 * required number left empty, which keeps its stored value. On a
 * create, only those the operator set, so the server fills the rest.
 */
export function buildBody(draft: StreamDraft, mode: 'create' | 'edit'): UpdateStreamRequest {
  const { protocol, tlsMode } = shapeOf(draft);
  const fields = fieldsFor(protocol, tlsMode);
  const body: Record<string, unknown> = {};
  for (const field of fields) {
    if (field in SCALAR_SPECS) {
      const scalar = field as ScalarField;
      let value = draft.scalars[scalar];
      if (scalar === 'port_last' && (value === null || value === '')) {
        // An empty last port is a single port: on an edit, the update
        // that leaves `port_last` out makes the stream one port.
        continue;
      }
      if (scalar === 'protocol') value = protocol;
      const out = scalarOf(scalar, value, mode);
      if (out.send) body[field] = out.value;
      continue;
    }
    switch (field) {
      case 'backend_ids':
        if (mode === 'edit' || draft.backend_ids.length > 0) body[field] = draft.backend_ids;
        break;
      case 'backup_backend_ids':
        if (mode === 'edit' || draft.backup_backend_ids.length > 0) body[field] = draft.backup_backend_ids;
        break;
      case 'backend_max_active': {
        const linked = caps(draft.backend_max_active, [...draft.backend_ids, ...draft.backup_backend_ids]);
        if (mode === 'edit' || Object.keys(linked).length > 0) body[field] = linked;
        break;
      }
      case 'match_rules':
        if (mode === 'edit' || draft.rules.length > 0) body[field] = draft.rules.map(ruleOf);
        break;
      case 'udp': {
        const udp = udpOf(draft);
        if (mode === 'edit' || Object.keys(udp).length > 0) body[field] = udp;
        break;
      }
      case 'geoip':
        if (draft.geoipMode === '') {
          if (mode === 'edit') body[field] = null;
        } else {
          body[field] = {
            mode: draft.geoipMode,
            countries: draft.geoipCountries.split(',').map((c) => c.trim()).filter((c) => c !== ''),
          };
        }
        break;
      case 'tls_terminate':
        if (mode === 'edit' || draft.certificateIds.length > 0 || draft.clientAuth) {
          body[field] = {
            certificate_ids: draft.certificateIds,
            client_auth: draft.clientAuth
              ? {
                  ca_cert_pem: draft.clientAuthCaPem,
                  required: draft.clientAuthRequired,
                  allowed_organizations: splitLines(draft.clientAuthOrganizations),
                }
              : null,
          };
        }
        break;
      case 'upstream_tls':
        if (!draft.upstreamTls) {
          if (mode === 'edit') body[field] = null;
        } else {
          const upstream: Record<string, unknown> = {
            skip_verify: draft.upstreamSkipVerify,
            alpn: splitLines(draft.upstreamAlpn),
            ca_cert_pem: draft.upstreamCaPem.trim() === '' ? null : draft.upstreamCaPem,
            client_certificate_id: draft.upstreamClientCertificateId === '' ? null : draft.upstreamClientCertificateId,
          };
          if (draft.upstreamServerName === 'fixed') {
            upstream.server_name = { mode: 'fixed', name: draft.upstreamFixedName.trim() };
          } else if (draft.upstreamServerName !== '') {
            upstream.server_name = { mode: draft.upstreamServerName };
          }
          body[field] = upstream;
        }
        break;
    }
  }
  return body as UpdateStreamRequest;
}

/** The body of a create: the four fields the server requires are the draft's own. */
export function buildCreateBody(draft: StreamDraft): CreateStreamRequest {
  return buildBody(draft, 'create') as CreateStreamRequest;
}
