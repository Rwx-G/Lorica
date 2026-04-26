import { describe, it, expect } from 'vitest';
import { formatBytes } from './format';

describe('formatBytes', () => {
  it('returns "0 B" for zero', () => {
    expect(formatBytes(0)).toBe('0 B');
  });

  it('returns "0 B" for negative inputs (defensive)', () => {
    expect(formatBytes(-1)).toBe('0 B');
    expect(formatBytes(-1024)).toBe('0 B');
  });

  it('returns "0 B" for NaN / Infinity (defensive)', () => {
    expect(formatBytes(NaN)).toBe('0 B');
    expect(formatBytes(Infinity)).toBe('0 B');
  });

  it('formats small byte counts as integral B (no decimal)', () => {
    expect(formatBytes(1)).toBe('1 B');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(1023)).toBe('1023 B');
  });

  it('binary units (default) use IEC suffixes (KiB / MiB / GiB)', () => {
    expect(formatBytes(1024)).toBe('1.0 KiB');
    expect(formatBytes(1024 * 1024)).toBe('1.0 MiB');
    expect(formatBytes(1024 ** 3)).toBe('1.0 GiB');
  });

  it('decimal units use SI suffixes (KB / MB / GB) - same divisor', () => {
    expect(formatBytes(1024, { units: 'decimal' })).toBe('1.0 KB');
    expect(formatBytes(1024 * 1024, { units: 'decimal' })).toBe('1.0 MB');
    expect(formatBytes(1024 ** 3, { units: 'decimal' })).toBe('1.0 GB');
  });

  it('respects custom precision', () => {
    expect(formatBytes(1500000, { precision: 2 })).toBe('1.43 MiB');
    expect(formatBytes(1500000, { precision: 0 })).toBe('1 MiB');
  });

  it('caps the suffix list at PiB / PB (no overflow into Exa+)', () => {
    const huge = 1024 ** 6; // 1 EiB worth of bytes
    const out = formatBytes(huge);
    expect(out.endsWith('PiB')).toBe(true);
  });

  it('regression : the M-20 reference value (1500000 bytes) is consistent', () => {
    // Pre-fix : System.svelte said "1.4 MB", Overview.svelte said
    // "1 MB", CertExportTab.svelte said "1.43 MiB".
    // Post-fix : every site that uses the helper sees the same
    // string for the same input.
    expect(formatBytes(1500000)).toBe('1.4 MiB');
    expect(formatBytes(1500000, { units: 'decimal' })).toBe('1.4 MB');
    expect(formatBytes(1500000, { units: 'decimal', precision: 2 })).toBe('1.43 MB');
  });
});
