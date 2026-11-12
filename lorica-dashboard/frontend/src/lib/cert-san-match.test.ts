import { describe, it, expect } from 'vitest';
import {
  canonicalIp,
  hostnameMatchesSan,
  hostnameCoveredByAny,
  findUncoveredHostnames,
} from './cert-san-match';

describe('hostnameMatchesSan - exact match', () => {
  it('matches identical names', () => {
    expect(hostnameMatchesSan('pki.example.com', 'pki.example.com')).toBe(true);
  });

  it('is case-insensitive on both sides', () => {
    expect(hostnameMatchesSan('PKI.Example.Com', 'pki.example.com')).toBe(true);
    expect(hostnameMatchesSan('pki.example.com', 'PKI.EXAMPLE.COM')).toBe(true);
  });

  it('strips a trailing FQDN dot on either side', () => {
    expect(hostnameMatchesSan('pki.example.com.', 'pki.example.com')).toBe(true);
    expect(hostnameMatchesSan('pki.example.com', 'pki.example.com.')).toBe(true);
  });

  it('trims surrounding whitespace', () => {
    expect(hostnameMatchesSan('  pki.example.com  ', 'pki.example.com')).toBe(true);
  });

  it('rejects different names', () => {
    expect(hostnameMatchesSan('pki.example.com', 'other.example.com')).toBe(false);
    expect(hostnameMatchesSan('pki.example.com', 'example.com')).toBe(false);
  });
});

describe('hostnameMatchesSan - wildcard match', () => {
  it('matches a single subdomain label', () => {
    expect(hostnameMatchesSan('pki.example.com', '*.example.com')).toBe(true);
    expect(hostnameMatchesSan('a.example.com', '*.example.com')).toBe(true);
  });

  it('does NOT match the apex', () => {
    expect(hostnameMatchesSan('example.com', '*.example.com')).toBe(false);
  });

  it('does NOT match multi-label substitutions', () => {
    expect(hostnameMatchesSan('a.b.example.com', '*.example.com')).toBe(false);
    expect(hostnameMatchesSan('deeply.nested.host.example.com', '*.example.com')).toBe(false);
  });

  it('rejects partial-label wildcards (RFC 6125 strict)', () => {
    expect(hostnameMatchesSan('pki.example.com', 'pki*.example.com')).toBe(false);
    expect(hostnameMatchesSan('pki.example.com', '*ki.example.com')).toBe(false);
  });

  it('rejects multi-wildcard SANs', () => {
    expect(hostnameMatchesSan('a.b.example.com', '*.*.example.com')).toBe(false);
  });

  it('rejects a bare "*" or "*."', () => {
    expect(hostnameMatchesSan('example.com', '*')).toBe(false);
    expect(hostnameMatchesSan('example.com', '*.')).toBe(false);
  });

  it('case-insensitive wildcard', () => {
    expect(hostnameMatchesSan('PKI.Example.Com', '*.example.com')).toBe(true);
    expect(hostnameMatchesSan('pki.example.com', '*.EXAMPLE.COM')).toBe(true);
  });

  it('does not let the suffix straddle a label boundary', () => {
    // "*.example.com" must require the host to have ".example.com"
    // as a suffix preceded by a single label, not just terminate in
    // those bytes - "myexample.com" must NOT match "*.example.com".
    expect(hostnameMatchesSan('myexample.com', '*.example.com')).toBe(false);
    expect(hostnameMatchesSan('foo.myexample.com', '*.example.com')).toBe(false);
  });
});

describe('hostnameMatchesSan - empty inputs', () => {
  it('rejects empty hostname', () => {
    expect(hostnameMatchesSan('', 'example.com')).toBe(false);
    expect(hostnameMatchesSan('   ', 'example.com')).toBe(false);
  });

  it('rejects empty SAN', () => {
    expect(hostnameMatchesSan('example.com', '')).toBe(false);
    expect(hostnameMatchesSan('example.com', '   ')).toBe(false);
  });
});

describe('hostnameCoveredByAny', () => {
  it('returns true when any SAN matches', () => {
    expect(
      hostnameCoveredByAny('pki.example.com', ['other.example.com', '*.example.com']),
    ).toBe(true);
  });

  it('returns false when no SAN matches', () => {
    expect(
      hostnameCoveredByAny('pki.example.com', ['other.example.com', '*.foo.example.com']),
    ).toBe(false);
  });

  it('returns false on empty SAN list', () => {
    expect(hostnameCoveredByAny('pki.example.com', [])).toBe(false);
  });
});

describe('findUncoveredHostnames', () => {
  it('returns the hostnames not covered by any SAN', () => {
    const result = findUncoveredHostnames(
      ['pki.example.com', 'api.example.com', 'admin.other.com'],
      ['*.example.com'],
    );
    expect(result).toEqual(['admin.other.com']);
  });

  it('returns empty when all hostnames are covered', () => {
    const result = findUncoveredHostnames(
      ['pki.example.com', 'example.com'],
      ['*.example.com', 'example.com'],
    );
    expect(result).toEqual([]);
  });

  it('skips empty / whitespace entries', () => {
    const result = findUncoveredHostnames(
      ['pki.example.com', '', '   '],
      ['*.example.com'],
    );
    expect(result).toEqual([]);
  });

  it('deduplicates case-insensitively in the input list', () => {
    const result = findUncoveredHostnames(
      ['admin.other.com', 'ADMIN.other.com', 'Admin.Other.Com'],
      ['*.example.com'],
    );
    expect(result).toEqual(['admin.other.com']);
  });

  it('preserves the original casing of the first occurrence', () => {
    const result = findUncoveredHostnames(
      ['Admin.Other.Com', 'admin.other.com'],
      ['*.example.com'],
    );
    expect(result).toEqual(['Admin.Other.Com']);
  });
});

describe('canonicalIp', () => {
  it('reads an IPv4 literal', () => {
    expect(canonicalIp('192.0.2.10')).toBe('192.0.2.10');
    expect(canonicalIp(' 192.0.2.10 ')).toBe('192.0.2.10');
  });

  it('canonicalises an IPv6 literal, with or without brackets', () => {
    expect(canonicalIp('2001:DB8:0:0:0:0:0:1')).toBe('[2001:db8::1]');
    expect(canonicalIp('[2001:db8::1]')).toBe('[2001:db8::1]');
    expect(canonicalIp('::1')).toBe('[::1]');
    expect(canonicalIp('[::1]')).toBe('[::1]');
  });

  it('is null for a DNS name or a malformed literal', () => {
    expect(canonicalIp('localhost')).toBeNull();
    expect(canonicalIp('pki.example.com')).toBeNull();
    expect(canonicalIp('999.0.2.10')).toBeNull();
    expect(canonicalIp('2001:db8::1::2')).toBeNull();
    expect(canonicalIp('')).toBeNull();
  });
});

// Issue #53: a route whose hostname is an IP, with a certificate that
// carries the IP as an IP address SAN.
describe('hostnameCoveredByAny - IP hostnames', () => {
  it('matches an IPv4 hostname against the IP SANs', () => {
    expect(hostnameCoveredByAny('192.168.153.1', ['localhost'], ['192.168.153.1'])).toBe(true);
    expect(hostnameCoveredByAny('192.168.153.2', ['localhost'], ['192.168.153.1'])).toBe(false);
  });

  it('matches an IPv6 hostname in any spelling', () => {
    expect(hostnameCoveredByAny('2001:db8::1', [], ['2001:db8::1'])).toBe(true);
    expect(hostnameCoveredByAny('[2001:db8::1]', [], ['2001:db8::1'])).toBe(true);
    expect(hostnameCoveredByAny('2001:DB8:0:0:0:0:0:1', [], ['2001:db8::1'])).toBe(true);
    expect(hostnameCoveredByAny('::1', [], ['2001:db8::1'])).toBe(false);
  });

  it('never matches an IP hostname against a DNS SAN', () => {
    expect(hostnameCoveredByAny('192.168.153.1', ['192.168.153.1'], [])).toBe(false);
    expect(hostnameCoveredByAny('::1', ['::1'])).toBe(false);
  });

  it('keeps the address families apart', () => {
    expect(hostnameCoveredByAny('192.0.2.10', [], ['::ffff:192.0.2.10'])).toBe(false);
    expect(hostnameCoveredByAny('::ffff:192.0.2.10', [], ['192.0.2.10'])).toBe(false);
  });

  it('never matches a DNS hostname against an IP SAN', () => {
    expect(hostnameCoveredByAny('localhost', [], ['127.0.0.1'])).toBe(false);
    expect(hostnameCoveredByAny('pki.example.com', ['*.example.com'], ['192.0.2.10'])).toBe(true);
  });
});

describe('findUncoveredHostnames - IP hostnames', () => {
  it('reports only the names neither SAN list covers', () => {
    const result = findUncoveredHostnames(
      ['192.168.153.1', 'localhost', '192.168.153.2', 'other.example.com'],
      ['localhost'],
      ['192.168.153.1'],
    );
    expect(result).toEqual(['192.168.153.2', 'other.example.com']);
  });
});
