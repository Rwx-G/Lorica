import { describe, it, expect } from 'vitest';
import {
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
