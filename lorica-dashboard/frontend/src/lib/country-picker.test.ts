import { describe, it, expect } from 'vitest';
import {
  parseCountryValue,
  serializeCountryValue,
  findIsoCodeInAncestry,
  toggleCountry,
} from './country-picker';

describe('parseCountryValue', () => {
  it('returns empty set for empty string', () => {
    expect(parseCountryValue('').size).toBe(0);
  });

  it('parses comma-separated list', () => {
    const s = parseCountryValue('FR, DE, US');
    expect(s.size).toBe(3);
    expect(s.has('FR')).toBe(true);
    expect(s.has('DE')).toBe(true);
    expect(s.has('US')).toBe(true);
  });

  it('parses whitespace-separated list', () => {
    const s = parseCountryValue('FR DE\tUS\nIT');
    expect(s.size).toBe(4);
  });

  it('upper-cases lowercase codes', () => {
    const s = parseCountryValue('fr, de, us');
    expect(s.has('FR')).toBe(true);
    expect(s.has('DE')).toBe(true);
    expect(s.has('US')).toBe(true);
  });

  it('dedupes repeated codes', () => {
    const s = parseCountryValue('FR, fr, FR, Fr');
    expect(s.size).toBe(1);
    expect(s.has('FR')).toBe(true);
  });

  it('filters entries that are not length-2', () => {
    const s = parseCountryValue('FR, USA, X, DE, FOO, IT');
    expect(s.size).toBe(3);
    expect(s.has('FR')).toBe(true);
    expect(s.has('DE')).toBe(true);
    expect(s.has('IT')).toBe(true);
    expect(s.has('USA')).toBe(false);
    expect(s.has('FOO')).toBe(false);
  });

  it('handles extra whitespace and empty entries', () => {
    const s = parseCountryValue('  FR ,, , DE   ');
    expect(s.size).toBe(2);
    expect(s.has('FR')).toBe(true);
    expect(s.has('DE')).toBe(true);
  });
});

describe('serializeCountryValue', () => {
  it('returns empty string for empty set', () => {
    expect(serializeCountryValue(new Set())).toBe('');
  });

  it('sorts codes deterministically', () => {
    expect(serializeCountryValue(new Set(['US', 'FR', 'DE']))).toBe('DE, FR, US');
  });

  it('round-trips through parseCountryValue', () => {
    const input = 'it, fr, de, us';
    const csv = serializeCountryValue(parseCountryValue(input));
    expect(csv).toBe('DE, FR, IT, US');
    const again = serializeCountryValue(parseCountryValue(csv));
    expect(again).toBe(csv);
  });
});

describe('findIsoCodeInAncestry', () => {
  function makeTree() {
    const root = document.createElement('div');
    const group = document.createElement('div');
    group.setAttribute('id', 'fr');
    const path = document.createElement('span');
    path.setAttribute('id', 'some-island-path');
    const leaf = document.createElement('span');
    group.appendChild(path);
    path.appendChild(leaf);
    root.appendChild(group);
    return { root, group, path, leaf };
  }

  it('returns upper-cased ISO from direct id', () => {
    const { group } = makeTree();
    expect(findIsoCodeInAncestry(group, null)).toBe('FR');
  });

  it('walks up to ancestor with length-2 id', () => {
    const { root, leaf } = makeTree();
    expect(findIsoCodeInAncestry(leaf, root)).toBe('FR');
  });

  it('stops at stopAt boundary', () => {
    const { group, leaf } = makeTree();
    expect(findIsoCodeInAncestry(leaf, group)).toBe(null);
  });

  it('returns null when no ancestor has length-2 id', () => {
    const orphan = document.createElement('div');
    orphan.setAttribute('id', 'background');
    expect(findIsoCodeInAncestry(orphan, null)).toBe(null);
  });

  it('returns null for null target', () => {
    expect(findIsoCodeInAncestry(null, null)).toBe(null);
  });

  it('ignores ids that are not exactly length 2', () => {
    const el = document.createElement('div');
    el.setAttribute('id', 'FRA');
    expect(findIsoCodeInAncestry(el, null)).toBe(null);
  });
});

describe('toggleCountry', () => {
  it('adds a country when absent', () => {
    const { next, csv } = toggleCountry(new Set(['FR']), 'DE');
    expect(next.has('FR')).toBe(true);
    expect(next.has('DE')).toBe(true);
    expect(csv).toBe('DE, FR');
  });

  it('removes a country when present', () => {
    const { next, csv } = toggleCountry(new Set(['FR', 'DE']), 'FR');
    expect(next.has('FR')).toBe(false);
    expect(next.has('DE')).toBe(true);
    expect(csv).toBe('DE');
  });

  it('does not mutate the input set', () => {
    const input = new Set(['FR']);
    toggleCountry(input, 'DE');
    expect(input.size).toBe(1);
    expect(input.has('FR')).toBe(true);
    expect(input.has('DE')).toBe(false);
  });

  it('returns empty csv when last country removed', () => {
    const { next, csv } = toggleCountry(new Set(['FR']), 'FR');
    expect(next.size).toBe(0);
    expect(csv).toBe('');
  });
});
