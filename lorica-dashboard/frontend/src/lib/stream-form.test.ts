// @vitest-environment node
/// <reference types="node" />
// The node environment gives `import.meta.url` the file: scheme the
// contract read below needs; nothing here touches the DOM.
import { readFileSync } from 'node:fs';
import { describe, it, expect } from 'vitest';

import type { StreamProtocol, StreamResponse, StreamTlsMode } from './api';
import {
  FIELD_TAB,
  SCALAR_SPECS,
  UDP_SPECS,
  buildBody,
  buildCreateBody,
  draftOf,
  fieldTab,
  fieldsFor,
  labelOf,
  newDraft,
  tabsFor,
  type ScalarSpec,
  type StreamField,
} from './stream-form';
import iv1Create from './stream-iv1-create.json';
import { stream, udpSettings } from '../test-stream-fixtures';

/** A stream of each (protocol, TLS mode) pair, every field it takes set, a port range so `port_last` is sent. */
function storedFor(protocol: StreamProtocol, tlsMode: StreamTlsMode): StreamResponse {
  const base = stream({ port_first: 6000, port_last: 6009, total_timeout_s: 3600, geoip: { mode: 'denylist', countries: ['XX'] } });
  if (protocol === 'udp') return { ...base, protocol, idle_timeout_s: 10, udp: udpSettings() };
  if (tlsMode === 'none') return { ...base, upstream_tls: { skip_verify: false, alpn: [] } };
  const rules = [
    { name: 'db', matcher: { kind: 'tls' as const, server_names: ['db.example.com'], alpn: [] }, backend_ids: ['b1'], backup_backend_ids: [], backend_max_active: {} },
  ];
  const tls = { ...base, tls_mode: tlsMode, match_rules: rules, backend_ids: [], clienthello_timeout_ms: 5000 };
  return tlsMode === 'terminate'
    ? { ...tls, tls_terminate: { certificate_ids: ['c1'], client_auth: null }, upstream_tls: null }
    : tls;
}

const PAIRS: [StreamProtocol, StreamTlsMode][] = [
  ['tcp', 'none'],
  ['tcp', 'passthrough'],
  ['tcp', 'terminate'],
  ['udp', 'none'],
];

/**
 * Fields the server refuses for each pair, as `openapi.yaml` words its
 * rules: the TCP-only settings and every TLS field on UDP, the
 * stream-level links and `upstream_tls` in passthrough, the rule fields
 * on a stream that does not route on TLS.
 */
const REFUSED: Record<string, StreamField[]> = {
  'tcp/none': ['udp', 'match_rules', 'clienthello_timeout_ms', 'tls_terminate', 'no_sni_acknowledged'],
  'tcp/passthrough': ['udp', 'backend_ids', 'backup_backend_ids', 'backend_max_active', 'tls_terminate', 'upstream_tls'],
  'tcp/terminate': ['udp', 'backend_ids', 'backup_backend_ids', 'backend_max_active'],
  'udp/none': [
    'tls_mode',
    'match_rules',
    'tls_terminate',
    'upstream_tls',
    'clienthello_timeout_ms',
    'no_sni_acknowledged',
    'proxy_protocol_accept',
    'proxy_protocol_trusted_cidrs',
    'max_connections',
    'connect_timeout_ms',
    'max_connect_attempts',
    'backend_keepalive',
    'backend_keepalive_idle_s',
    'close_on_backend_down',
    'upload_rate_bps',
    'download_rate_bps',
    'source_max_connections',
    'max_pending_connections',
  ],
};

describe('fieldsFor and the body an edit sends', () => {
  it.each(PAIRS)('sends exactly the fields it shows for %s/%s', (protocol, tlsMode) => {
    const body = buildBody(draftOf(storedFor(protocol, tlsMode)), 'edit');
    expect(new Set(Object.keys(body))).toEqual(new Set(fieldsFor(protocol, tlsMode)));
  });

  it.each(PAIRS)('never shows a field the server refuses for %s/%s', (protocol, tlsMode) => {
    const shown = fieldsFor(protocol, tlsMode);
    for (const field of REFUSED[`${protocol}/${tlsMode}`]) expect(shown.has(field), field).toBe(false);
  });

  it('places every writable field on a tab, and shows only tabs holding one', () => {
    for (const [protocol, tlsMode] of PAIRS) {
      for (const field of fieldsFor(protocol, tlsMode)) {
        expect(tabsFor(protocol, tlsMode)).toContain(FIELD_TAB[field]);
      }
    }
    expect(tabsFor('udp', 'none')).not.toContain('tls');
    expect(tabsFor('tcp', 'none')).not.toContain('udp');
    // A TLS stream links its backends per rule, on the Backends tab.
    expect(tabsFor('tcp', 'passthrough')).toContain('backends');
  });
});

describe('the body a create sends', () => {
  it('sends only what the operator set: the IV1 request', () => {
    const draft = newDraft();
    draft.scalars.name = iv1Create.name;
    draft.scalars.port_first = iv1Create.port_first;
    draft.backend_ids = iv1Create.backend_ids;
    expect(buildCreateBody(draft)).toEqual(iv1Create);
  });

  it('leaves an empty optional field to the server on a create, and clears it to null on an edit', () => {
    const create = newDraft();
    create.scalars.name = 'pg';
    create.scalars.port_first = 5432;
    expect('total_timeout_s' in buildCreateBody(create)).toBe(false);

    const edit = draftOf(stream({ total_timeout_s: 3600 }));
    edit.scalars.total_timeout_s = null;
    expect(buildBody(edit, 'edit').total_timeout_s).toBeNull();
  });

  it('keeps a required number left empty on an edit as stored, by not sending it', () => {
    const edit = draftOf(stream());
    edit.scalars.connect_timeout_ms = null;
    expect('connect_timeout_ms' in buildBody(edit, 'edit')).toBe(false);
  });

  it('sends a single port by leaving port_last out', () => {
    const edit = draftOf(stream({ port_first: 5432, port_last: 5432 }));
    expect('port_last' in buildBody(edit, 'edit')).toBe(false);
  });
});

describe('a protocol switch', () => {
  it('sends no udp key once a UDP stream turns TCP', () => {
    const draft = draftOf(stream({ protocol: 'udp', udp: udpSettings() }));
    draft.scalars.protocol = 'tcp';
    const body = buildBody(draft, 'edit');
    expect(body.protocol).toBe('tcp');
    expect('udp' in body).toBe(false);
  });

  it('sends no TCP-only or TLS key once a TCP stream turns UDP, and lets the server fill udp', () => {
    const draft = draftOf(storedFor('tcp', 'terminate'));
    draft.scalars.protocol = 'udp';
    const body = buildBody(draft, 'edit');
    for (const field of REFUSED['udp/none']) expect(field in body, field).toBe(false);
    expect(body.udp).toEqual({});
  });
});

describe('UDP settings', () => {
  it('sends requests_per_session null for no bound, and an empty one not at all', () => {
    const draft = draftOf(stream({ protocol: 'udp', udp: udpSettings() }));
    draft.udpRequestsUnbounded = true;
    expect(buildBody(draft, 'edit').udp?.requests_per_session).toBeNull();
    draft.udpRequestsUnbounded = false;
    draft.udp.requests_per_session = null;
    expect('requests_per_session' in (buildBody(draft, 'edit').udp ?? {})).toBe(false);
  });

  it('reads a stored null requests_per_session as no bound', () => {
    expect(draftOf(stream({ protocol: 'udp', udp: udpSettings({ requests_per_session: null }) })).udpRequestsUnbounded).toBe(true);
  });
});

describe('fieldTab', () => {
  it('routes a refusal naming each field to the tab holding it', () => {
    for (const field of Object.keys(FIELD_TAB) as StreamField[]) {
      expect(fieldTab(`${field} is out of range`), field).toBe(FIELD_TAB[field]);
      expect(fieldTab(`stream pg: ${field}: refused`), field).toBe(FIELD_TAB[field]);
    }
  });

  it('reads a field whole, never inside a longer one', () => {
    expect(fieldTab('source_max_connections must be at most max_pending_connections')).toBe('protection');
    expect(fieldTab('max_connections must be positive')).toBe('connection');
  });

  it("puts a UDP setting on the UDP tab and a rule's links on the Backends tab", () => {
    expect(fieldTab('udp.max_sessions must be between 1 and 1048576')).toBe('udp');
    expect(fieldTab('match_rules[0].backend_ids names no backend')).toBe('backends');
    expect(fieldTab('match_rules[0].matcher.server_names must not be empty')).toBe('tls');
  });

  it('falls back to General when no field is named', () => {
    expect(fieldTab('stream port conflict on host01')).toBe('general');
  });
});

const OPENAPI = readFileSync(new URL('../../../../lorica-api/openapi.yaml', import.meta.url), 'utf8').replace(/\r\n/g, '\n');

/**
 * The properties of an `openapi.yaml` schema whose description says the
 * value holds per node: the API contract's own statement of which
 * fields are caps (12.6 D-k), read rather than retyped here.
 */
function perNodeInContract(schema: string): Set<string> {
  const lines = OPENAPI.split('\n');
  const start = lines.indexOf(`    ${schema}:`);
  expect(start, `${schema} in openapi.yaml`).toBeGreaterThan(-1);
  const end = lines.findIndex((line, i) => i > start && /^ {4}\S/.test(line));
  const descriptions: Record<string, string> = {};
  let property = '';
  for (const line of lines.slice(start + 1, end)) {
    const name = /^ {8}([a-z0-9_]+):\s*$/.exec(line);
    if (name) {
      property = name[1];
      descriptions[property] = '';
    } else if (property && line.startsWith(' '.repeat(10))) {
      descriptions[property] += ` ${line.trim()}`;
    }
  }
  return new Set(Object.keys(descriptions).filter((p) => /\bper\s+node\b/.test(descriptions[p])));
}

function perNodeSpecs<K extends string>(specs: Record<K, ScalarSpec>): K[] {
  return (Object.keys(specs) as K[]).filter((field) => specs[field].perNode);
}

describe('every cap is labelled per node (12.6 D-k)', () => {
  it.each(perNodeSpecs(SCALAR_SPECS))('%s', (field) => {
    expect(labelOf(SCALAR_SPECS[field])).toMatch(/\(per node\)$/);
  });

  it.each(perNodeSpecs(UDP_SPECS))('udp.%s', (field) => {
    expect(labelOf(UDP_SPECS[field])).toMatch(/\(per node\)$/);
  });

  it('flags as perNode exactly the stream fields the API documents per node', () => {
    const contract = [...perNodeInContract('StreamResponse')];
    // The link cap is edited per backend, and LinkSet labels it.
    expect(contract.filter((field) => !(field in SCALAR_SPECS))).toEqual(['backend_max_active']);
    expect(new Set<string>(perNodeSpecs(SCALAR_SPECS))).toEqual(new Set(contract.filter((field) => field in SCALAR_SPECS)));
  });

  it('flags as perNode exactly the UDP settings the API documents per node', () => {
    expect(new Set<string>(perNodeSpecs(UDP_SPECS))).toEqual(perNodeInContract('StreamUdpSettings'));
  });
});
