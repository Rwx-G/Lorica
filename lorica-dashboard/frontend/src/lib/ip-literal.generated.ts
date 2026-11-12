// Rendered from lorica-config's `host_shape` by
// lorica-api/tests/ip_literal_fixture.rs, which prints the file as it must
// read when the committed one differs. Replace the file with that; never
// edit it by hand.

/** What a host name is to a browser's URL parser (`HostShape::kind`). */
export type HostKind = 'ipv4' | 'ipv6' | 'non_canonical_ipv4' | 'not_an_address';

/**
 * One name, what it is, and the address as a route stores it and a request
 * names it (`HostShape::canonical`, `null` for no address).
 */
export interface HostShapeVector {
  readonly input: string;
  readonly kind: HostKind;
  readonly canonical: string | null;
}

export const HOST_SHAPE_VECTORS: readonly HostShapeVector[] = [
  { input: '192.0.2.10', kind: 'ipv4', canonical: '192.0.2.10' },
  { input: '0.0.0.0', kind: 'ipv4', canonical: '0.0.0.0' },
  { input: '255.255.255.255', kind: 'ipv4', canonical: '255.255.255.255' },
  { input: '192.0.2.10.', kind: 'ipv4', canonical: '192.0.2.10' },
  { input: '010.0.0.1', kind: 'non_canonical_ipv4', canonical: null },
  { input: '192.0.2.010', kind: 'non_canonical_ipv4', canonical: null },
  { input: '00.0.0.0', kind: 'non_canonical_ipv4', canonical: null },
  { input: '0xC0.0.2.10', kind: 'non_canonical_ipv4', canonical: null },
  { input: '0XC0.0.2.10', kind: 'non_canonical_ipv4', canonical: null },
  { input: '0xc0.0x0.0x2.0xa', kind: 'non_canonical_ipv4', canonical: null },
  { input: '3221225994', kind: 'non_canonical_ipv4', canonical: null },
  { input: '0xc000020a', kind: 'non_canonical_ipv4', canonical: null },
  { input: '030000001012', kind: 'non_canonical_ipv4', canonical: null },
  { input: '192.0.10', kind: 'non_canonical_ipv4', canonical: null },
  { input: '192.10', kind: 'non_canonical_ipv4', canonical: null },
  { input: '1', kind: 'non_canonical_ipv4', canonical: null },
  { input: '0x', kind: 'non_canonical_ipv4', canonical: null },
  { input: '256.0.0.1', kind: 'non_canonical_ipv4', canonical: null },
  { input: '1.2.3.256', kind: 'non_canonical_ipv4', canonical: null },
  { input: '1.2.3.4.5', kind: 'non_canonical_ipv4', canonical: null },
  { input: 'example.123', kind: 'non_canonical_ipv4', canonical: null },
  { input: 'example.0x1f', kind: 'non_canonical_ipv4', canonical: null },
  { input: 'example.010', kind: 'non_canonical_ipv4', canonical: null },
  { input: '*.0.2.10', kind: 'non_canonical_ipv4', canonical: null },
  { input: '*.10', kind: 'non_canonical_ipv4', canonical: null },
  { input: 'app.example.com', kind: 'not_an_address', canonical: null },
  { input: 'App.Example.COM', kind: 'not_an_address', canonical: null },
  { input: 'app.example.com.', kind: 'not_an_address', canonical: null },
  { input: 'localhost', kind: 'not_an_address', canonical: null },
  { input: '_', kind: 'not_an_address', canonical: null },
  { input: '*.example.com', kind: 'not_an_address', canonical: null },
  { input: '192.0.2.10.example.org', kind: 'not_an_address', canonical: null },
  { input: '10.example', kind: 'not_an_address', canonical: null },
  { input: 'v10', kind: 'not_an_address', canonical: null },
  { input: 'example.0xg', kind: 'not_an_address', canonical: null },
  { input: '0x.example', kind: 'not_an_address', canonical: null },
  { input: '192.0.2.10..', kind: 'not_an_address', canonical: null },
  { input: '', kind: 'not_an_address', canonical: null },
  { input: '.', kind: 'not_an_address', canonical: null },
  { input: 'bücher.example', kind: 'not_an_address', canonical: null },
  { input: '[2001:db8::1]', kind: 'ipv6', canonical: '[2001:db8::1]' },
  { input: '[2001:DB8:0:0:0:0:0:1]', kind: 'ipv6', canonical: '[2001:db8::1]' },
  { input: '2001:db8::1', kind: 'ipv6', canonical: '[2001:db8::1]' },
  { input: '2001:0db8:0000:0000:0000:0000:0000:0001', kind: 'ipv6', canonical: '[2001:db8::1]' },
  { input: '[2001:db8::1].', kind: 'ipv6', canonical: '[2001:db8::1]' },
  { input: '[::1]', kind: 'ipv6', canonical: '[::1]' },
  { input: '::', kind: 'ipv6', canonical: '[::]' },
  { input: '[::]', kind: 'ipv6', canonical: '[::]' },
  { input: '[2001:db8:0:1:0:0:0:1]', kind: 'ipv6', canonical: '[2001:db8:0:1::1]' },
  { input: '[1:0:0:2:0:0:0:3]', kind: 'ipv6', canonical: '[1:0:0:2::3]' },
  { input: '[0:0:1:0:0:0:0:0]', kind: 'ipv6', canonical: '[0:0:1::]' },
  { input: '[::ffff:192.0.2.10]', kind: 'ipv6', canonical: '[::ffff:192.0.2.10]' },
  { input: '::ffff:c000:20a', kind: 'ipv6', canonical: '[::ffff:192.0.2.10]' },
  { input: '[::FFFF:C000:20A]', kind: 'ipv6', canonical: '[::ffff:192.0.2.10]' },
  { input: '[::192.0.2.10]', kind: 'ipv6', canonical: '[::c000:20a]' },
  { input: '[fe80::1%25eth0]', kind: 'not_an_address', canonical: null },
  { input: 'fe80::1%eth0', kind: 'not_an_address', canonical: null },
  { input: '192.0.2.10:443', kind: 'not_an_address', canonical: null },
  { input: '[2001:db8::1]:443', kind: 'not_an_address', canonical: null },
  { input: 'app.example.com:8443', kind: 'not_an_address', canonical: null },
  { input: '[not-an-address]', kind: 'not_an_address', canonical: null },
  { input: '[192.0.2.10]', kind: 'not_an_address', canonical: null },
  { input: '[2001:db8::1', kind: 'not_an_address', canonical: null },
  { input: '2001:db8::1]', kind: 'not_an_address', canonical: null },
  { input: '2001:db8::1::2', kind: 'not_an_address', canonical: null },
  { input: '12345::1', kind: 'not_an_address', canonical: null },
  { input: '[::ffff:01.2.3.4]', kind: 'not_an_address', canonical: null },
];
