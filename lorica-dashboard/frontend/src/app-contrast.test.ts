// @vitest-environment node
/// <reference types="node" />
import { readFileSync } from 'node:fs';

import { describe, it, expect } from 'vitest';

// Read from disk: Vitest serves CSS modules, `?raw` included, as empty
// strings unless CSS processing is enabled for the whole suite. The node
// environment gives `import.meta.url` its file: scheme; jsdom does not.
const appCss = readFileSync(new URL('./app.css', import.meta.url), 'utf8');

// Badge text contrast, computed from the theme tokens in app.css rather
// than from values copied here, so a token change that drops a badge
// under WCAG AA fails this file.

type Rgba = [number, number, number, number];

const AA = 4.5;

function themeTokens(selector: string): Map<string, Rgba> {
  const escaped = selector.replace(/[[\]"]/g, '\\$&');
  const block = new RegExp(`${escaped}\\s*\\{([^}]*)\\}`).exec(appCss);
  if (!block) throw new Error(`no ${selector} block in app.css`);
  const body = block[1].replace(/\/\*[\s\S]*?\*\//g, '');
  const tokens = new Map<string, Rgba>();
  for (const [, name, value] of body.matchAll(/(--color-[\w-]+):\s*([^;]+);/g)) {
    const color = parseColor(value.trim());
    if (color) tokens.set(name, color);
  }
  return tokens;
}

function parseColor(value: string): Rgba | null {
  const hex = /^#([0-9a-f]{6})$/i.exec(value);
  if (hex) {
    const n = parseInt(hex[1], 16);
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255, 1];
  }
  const rgba = /^rgba\((\d+),\s*(\d+),\s*(\d+),\s*([\d.]+)\)$/.exec(value);
  if (rgba) return [+rgba[1], +rgba[2], +rgba[3], +rgba[4]];
  return null;
}

function over(top: Rgba, base: Rgba): Rgba {
  const a = top[3];
  return [0, 1, 2].map((i) => top[i] * a + base[i] * (1 - a)).concat(1) as Rgba;
}

function luminance([r, g, b]: Rgba): number {
  const lin = (v: number) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

function contrast(a: Rgba, b: Rgba): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

const THEMES = {
  light: themeTokens(':root[data-theme="light"]'),
  dark: themeTokens(':root[data-theme="dark"]'),
};

function token(theme: Map<string, Rgba>, name: string): Rgba {
  const value = theme.get(name);
  if (!value) throw new Error(`${name} is not a colour token of this theme`);
  return value;
}

const toastCss = readFileSync(new URL('./components/Toast.svelte', import.meta.url), 'utf8');

/** The declarations of `selector`'s rule in `css`. */
function cssRule(css: string, selector: string): string {
  const escaped = selector.replace(/[.]/g, '\\$&');
  const block = new RegExp(`${escaped}\\s*\\{([^}]*)\\}`).exec(css);
  if (!block) throw new Error(`no ${selector} rule`);
  return block[1];
}

/** The colour tokens one property of a rule names, in order, at least one. */
function declaredTokens(rule: string, property: string): string[] {
  const declaration = new RegExp(`(?:^|[;\\s])${property}:\\s*([^;]+);`).exec(rule);
  if (!declaration) throw new Error(`no ${property} in the rule`);
  const names = [...new Set([...declaration[1].matchAll(/var\((--color-[\w-]+)\)/g)].map((m) => m[1]))];
  if (names.length === 0) throw new Error(`${property} names no colour token`);
  return names;
}

/** Every opaque surface a badge sits on, with and without row hover. */
function surfaces(theme: Map<string, Rgba>): Rgba[] {
  const hover = token(theme, '--color-bg-hover');
  return ['--color-bg', '--color-bg-card', '--color-bg-elevated', '--color-bg-input']
    .map((name) => token(theme, name))
    .flatMap((s) => [s, over(hover, s)]);
}

describe.each(Object.entries(THEMES))('badge text contrast, %s theme', (_, theme) => {
  it.each(['green', 'orange', 'red', 'primary'])(
    '--color-%s-text holds AA on its tint on every surface',
    (family) => {
      const text = token(theme, `--color-${family}-text`);
      const tint = token(theme, `--color-${family}-subtle`);
      for (const surface of surfaces(theme)) {
        expect(contrast(text, over(tint, surface))).toBeGreaterThanOrEqual(AA);
      }
    },
  );

  it.each(['red', 'primary'])('--color-text-on-solid holds AA on solid --color-%s', (family) => {
    const text = token(theme, '--color-text-on-solid');
    expect(contrast(text, token(theme, `--color-${family}`))).toBeGreaterThanOrEqual(AA);
  });

  it('--color-text holds AA on the neutral badge surface', () => {
    const text = token(theme, '--color-text');
    for (const surface of surfaces(theme)) {
      expect(contrast(text, surface)).toBeGreaterThanOrEqual(AA);
    }
  });

  it('the warning toast holds AA on its own background', () => {
    const rule = cssRule(toastCss, '.toast-warning');
    const [base] = declaredTokens(rule, 'background-color');
    const surface = token(theme, base);
    // A toast floats over the page: a translucent base would let
    // whatever is under it decide the contrast.
    expect(surface[3]).toBe(1);
    const background = declaredTokens(rule, 'background-image')
      .map((name) => token(theme, name))
      .reduce((under, layer) => over(layer, under), surface);
    const [text] = declaredTokens(rule, 'color');
    expect(contrast(token(theme, text), background)).toBeGreaterThanOrEqual(AA);
  });
});
