import { describe, it, expect } from 'vitest';
import { isDynamicImportError } from './chunk-reload';

describe('isDynamicImportError', () => {
  it('matches Chrome "Failed to fetch dynamically imported module"', () => {
    const msg =
      'Failed to fetch dynamically imported module: https://example.com/assets/System-BKmnQ-yI.js';
    expect(isDynamicImportError(msg)).toBe(true);
  });

  it('matches Chrome short form "error loading dynamically imported module"', () => {
    const msg =
      'error loading dynamically imported module: https://example.com/assets/System-BKmnQ-yI.js';
    expect(isDynamicImportError(msg)).toBe(true);
  });

  it('matches Firefox / Safari "Importing a module script failed"', () => {
    expect(isDynamicImportError('Importing a module script failed.')).toBe(
      true,
    );
  });

  it('does not match an unrelated error', () => {
    expect(isDynamicImportError('TypeError: foo is not a function')).toBe(
      false,
    );
  });

  it('does not match an empty message', () => {
    expect(isDynamicImportError('')).toBe(false);
  });

  it('does not match a network error that is not import-related', () => {
    expect(isDynamicImportError('NetworkError when attempting to fetch resource.')).toBe(
      false,
    );
  });
});
