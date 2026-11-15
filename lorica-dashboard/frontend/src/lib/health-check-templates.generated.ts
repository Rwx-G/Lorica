// Rendered from Rust by lorica-api/tests/health_check_template_fixture.rs, which
// prints the whole file as it must read when the committed one differs. Replace
// the file with that output; never edit it by hand.

/** Where an expected answer must appear in the bytes a probe reads (`MatchAnchor`). */
export type MatchAnchor = 'prefix' | 'contains';

/**
 * Bytes as a template carries them: lowercase `hex`, and the same bytes
 * `shown` with printable ASCII kept, `\r`, `\n`, `\t` and `\\` escaped, and
 * every other byte as `\xNN`.
 */
export interface TemplateBytes {
  readonly hex: string;
  readonly shown: string;
}

/** One answer a template accepts. */
export interface TemplateExpectation {
  readonly match: MatchAnchor;
  readonly bytes: TemplateBytes;
}

/** The name a `tcp_template` check stores. */
export type TcpCheckTemplateName = 'redis_ping' | 'smtp_banner' | 'postgresql_ssl_request';

/** A TCP check the release ships, referenced by name (`CheckTemplate`). */
export interface CheckTemplate {
  readonly name: TcpCheckTemplateName;
  readonly summary: string;
  readonly send: TemplateBytes | null;
  readonly expect: readonly TemplateExpectation[];
}

/** Every template, in `TCP_CHECK_TEMPLATES` order. */
export const TCP_CHECK_TEMPLATES: readonly CheckTemplate[] = [
  {
    name: 'redis_ping',
    summary: 'Redis: PING answered by +PONG, or by -NOAUTH from a server that requires authentication (it is up and speaking its protocol)',
    send: { hex: '50494e470d0a', shown: 'PING\\r\\n' },
    expect: [
      { match: 'prefix', bytes: { hex: '2b504f4e47', shown: '+PONG' } },
      { match: 'prefix', bytes: { hex: '2d4e4f41555448', shown: '-NOAUTH' } },
    ],
  },
  {
    name: 'smtp_banner',
    summary: 'SMTP: the server\'s greeting starts with 220',
    send: null,
    expect: [
      { match: 'prefix', bytes: { hex: '323230', shown: '220' } },
    ],
  },
  {
    name: 'postgresql_ssl_request',
    summary: 'PostgreSQL: an SSLRequest answered by S (TLS offered) or N (TLS declined)',
    send: { hex: '0000000804d2162f', shown: '\\x00\\x00\\x00\\x08\\x04\\xd2\\x16/' },
    expect: [
      { match: 'prefix', bytes: { hex: '53', shown: 'S' } },
      { match: 'prefix', bytes: { hex: '4e', shown: 'N' } },
    ],
  },
];

// The limits a custom send/expect check is held to when written, by their Rust names.
/** The most bytes a custom `send` carries, decoded. */
export const SEND_MAX_BYTES = 1024;
/** The most alternatives a custom `expect` lists. */
export const EXPECT_MAX_ALTERNATIVES = 8;
/** The most bytes one expected alternative carries, decoded. */
export const EXPECT_MAX_BYTES = 256;
/** The most bytes one probe reads, whatever the check says. */
export const PROBE_READ_MAX_BYTES = 4096;
/** The shortest `timeout_ms` a check may set. */
export const PROBE_TIMEOUT_MS_MIN = 100;
/** The longest `timeout_ms` a check may set. */
export const PROBE_TIMEOUT_MS_MAX = 10000;
/** The `timeout_ms` of a check that sets none. */
export const PROBE_TIMEOUT_MS_DEFAULT = 5000;
