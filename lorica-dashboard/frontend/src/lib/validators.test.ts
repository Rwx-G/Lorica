import { describe, it, expect } from 'vitest';
import {
  parseOctalMode,
  validateAbsolutePath,
  validateCertExportPattern,
  validateOctalMode,
  validatePosixId,
} from './validators';

describe('validateAbsolutePath', () => {
  it('accepts empty string (feature off)', () => {
    expect(validateAbsolutePath('')).toBeNull();
    expect(validateAbsolutePath('   ')).toBeNull();
  });

  it('accepts a plain absolute path', () => {
    expect(validateAbsolutePath('/var/lib/lorica/exported-certs')).toBeNull();
    expect(validateAbsolutePath('/etc/lorica')).toBeNull();
  });

  it('rejects a relative path', () => {
    expect(validateAbsolutePath('var/lib/x')).toMatch(/absolute/);
    expect(validateAbsolutePath('./relative')).toMatch(/absolute/);
  });

  it('rejects path traversal', () => {
    expect(validateAbsolutePath('/var/lib/../etc/shadow')).toMatch(/traversal/);
    expect(validateAbsolutePath('/var/lib/..')).toMatch(/traversal/);
  });

  it('rejects a path too long', () => {
    const long = '/' + 'a'.repeat(4096);
    expect(validateAbsolutePath(long)).toMatch(/too long/);
  });

  it('rejects a control character', () => {
    expect(validateAbsolutePath('/var/lib/lo\u0001rica')).toMatch(/control/);
  });
});

describe('validateOctalMode', () => {
  it('accepts empty string', () => {
    expect(validateOctalMode('')).toBeNull();
    expect(validateOctalMode('   ')).toBeNull();
  });

  it('accepts bare octal digits', () => {
    expect(validateOctalMode('640')).toBeNull();
    expect(validateOctalMode('755')).toBeNull();
    expect(validateOctalMode('600')).toBeNull();
    expect(validateOctalMode('0')).toBeNull();
    expect(validateOctalMode('777')).toBeNull();
  });

  it('accepts leading 0 and 0o prefixes', () => {
    expect(validateOctalMode('0640')).toBeNull();
    expect(validateOctalMode('0o640')).toBeNull();
    expect(validateOctalMode('0O640')).toBeNull();
  });

  it('rejects non-octal digits', () => {
    expect(validateOctalMode('678')).toMatch(/octal/);
    expect(validateOctalMode('abc')).toMatch(/octal/);
    expect(validateOctalMode('6.4')).toMatch(/octal/);
  });

  it('rejects modes past 0o777', () => {
    expect(validateOctalMode('1000')).toMatch(/9 permission bits/);
    expect(validateOctalMode('7777')).toMatch(/9 permission bits/);
  });
});

describe('parseOctalMode', () => {
  it('returns null for empty / invalid input', () => {
    expect(parseOctalMode('')).toBeNull();
    expect(parseOctalMode('abc')).toBeNull();
    expect(parseOctalMode('9')).toBeNull();
    expect(parseOctalMode('1000')).toBeNull();
  });

  it('parses octal into decimal', () => {
    expect(parseOctalMode('640')).toBe(0o640);
    expect(parseOctalMode('0o640')).toBe(0o640);
    expect(parseOctalMode('0640')).toBe(0o640);
    expect(parseOctalMode('750')).toBe(0o750);
    expect(parseOctalMode('0')).toBe(0);
    expect(parseOctalMode('777')).toBe(0o777);
  });
});

describe('validatePosixId', () => {
  it('accepts empty string (unset)', () => {
    expect(validatePosixId('')).toBeNull();
    expect(validatePosixId('   ')).toBeNull();
  });

  it('accepts a non-negative integer', () => {
    expect(validatePosixId('0')).toBeNull();
    expect(validatePosixId('1001')).toBeNull();
    expect(validatePosixId('65534')).toBeNull();
  });

  it('rejects negatives and decimals', () => {
    expect(validatePosixId('-1')).toMatch(/non-negative/);
    expect(validatePosixId('1.5')).toMatch(/non-negative/);
    expect(validatePosixId('abc')).toMatch(/non-negative/);
  });

  it('rejects values past u32', () => {
    expect(validatePosixId('4294967296')).toMatch(/u32/);
    expect(validatePosixId('99999999999')).toMatch(/u32/);
  });

  it('accepts u32 ceiling', () => {
    expect(validatePosixId('4294967295')).toBeNull();
  });
});

describe('validateCertExportPattern', () => {
  it('accepts exact hostname, wildcard suffix, and catch-all', () => {
    expect(validateCertExportPattern('grafana.mibu.fr')).toBeNull();
    expect(validateCertExportPattern('*.mibu.fr')).toBeNull();
    expect(validateCertExportPattern('*')).toBeNull();
  });

  it('rejects an interior wildcard', () => {
    expect(validateCertExportPattern('foo.*.bar')).toMatch(/leading/);
    expect(validateCertExportPattern('*.foo.*.bar')).toMatch(/empty DNS label|leading/);
  });

  it('rejects empty input', () => {
    expect(validateCertExportPattern('')).toMatch(/not be empty/);
    expect(validateCertExportPattern('   ')).toMatch(/not be empty/);
  });

  it('rejects dots at the edges', () => {
    expect(validateCertExportPattern('.bad.com')).toMatch(/start or end with a dot/);
    expect(validateCertExportPattern('bad.com.')).toMatch(/start or end with a dot/);
  });

  it('rejects empty DNS labels', () => {
    expect(validateCertExportPattern('bad..com')).toMatch(/empty DNS label/);
  });

  it('rejects non-ASCII and underscores', () => {
    expect(validateCertExportPattern('my_group.com')).toMatch(/ASCII/);
    expect(validateCertExportPattern('café.com')).toMatch(/ASCII/);
  });

  it('rejects labels past 63 characters', () => {
    const long = 'a'.repeat(64);
    expect(validateCertExportPattern(`*.${long}.com`)).toMatch(/63/);
  });

  it('rejects patterns past 253 characters', () => {
    const long = 'a'.repeat(254);
    expect(validateCertExportPattern(long)).toMatch(/253/);
  });
});
