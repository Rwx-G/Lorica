/**
 * Stream fixtures shared by the Streams page, the stream form and the
 * Backends page tests (Story 12.10). Values are the server defaults
 * `openapi.yaml` documents for `StreamResponse`, so a test overrides
 * only what it is about.
 */

import type { StreamReadResponse, StreamStatus, StreamUdpSettings } from './lib/api';

export function udpSettings(overrides: Partial<StreamUdpSettings> = {}): StreamUdpSettings {
  return {
    max_sessions: 4096,
    source_session_cap: null,
    requests_per_session: 64,
    responses_per_request: 1,
    response_bytes_ratio: 32,
    unbounded_responses: false,
    source_datagram_rate: 1000,
    source_byte_rate: 524288,
    max_datagram_bytes: 8192,
    ...overrides,
  };
}

export function stream(overrides: Partial<StreamReadResponse> = {}): StreamReadResponse {
  return {
    id: 'pg-id',
    name: 'pg',
    group_name: '',
    protocol: 'tcp',
    enabled: true,
    listen_address: '0.0.0.0',
    port_first: 5432,
    port_last: 5432,
    node_selector: [],
    load_balancing: 'round_robin',
    connect_timeout_ms: 5000,
    idle_timeout_s: 600,
    total_timeout_s: null,
    max_connect_attempts: 3,
    backend_keepalive: true,
    backend_keepalive_idle_s: 60,
    close_on_backend_down: false,
    proxy_protocol_send: 'off',
    proxy_protocol_accept: false,
    proxy_protocol_trusted_cidrs: [],
    source_addresses: [],
    allow_local_backend: false,
    upload_rate_bps: null,
    download_rate_bps: null,
    max_connections: 1024,
    source_max_connections: null,
    max_pending_connections: 256,
    source_allow_cidrs: [],
    source_deny_cidrs: [],
    geoip: null,
    source_open_rate: null,
    open_rate: null,
    udp: null,
    tls_mode: 'none',
    match_rules: [],
    no_sni_acknowledged: false,
    clienthello_timeout_ms: null,
    tls_terminate: null,
    upstream_tls: null,
    drains_on_upgrade: false,
    backend_ids: ['b1'],
    backup_backend_ids: [],
    backend_max_active: {},
    created_at: '2026-11-18T10:00:00Z',
    updated_at: '2026-11-18T10:00:00Z',
    bind: { state: 'bound', workers_serving: 2, workers: 2 },
    ...overrides,
  };
}

export function status(overrides: Partial<StreamStatus> = {}): StreamStatus {
  return {
    id: 'pg-id',
    name: 'pg',
    protocol: 'tcp',
    bind: { state: 'bound', workers_serving: 2, workers: 2 },
    nodes: null,
    counters: null,
    ...overrides,
  };
}
