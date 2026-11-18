// @vitest-environment node
/// <reference types="node" />
import { readFileSync } from 'node:fs';

import { describe, it, expect } from 'vitest';

// Read from disk: Vitest serves CSS imports, `?raw` included, as empty
// strings, and only the node environment gives `import.meta.url` its
// file: scheme.
const appCss = readFileSync(new URL('./app.css', import.meta.url), 'utf8');

// app.css gives `.settings-table` fixed widths that already add up to
// 100% over its first columns, under `table-layout: fixed`. Any column
// past those gets no width and is drawn over its neighbours, which is
// how the automation token table's "Last used" and "Revoke" ended up on
// top of each other. A wider table must opt out with
// `settings-table-wide`.
const FIXED_LAYOUT_COLUMNS = appCss.match(/^\.settings-table th:nth-child\(\d+\)/gm)?.length ?? 0;

const sources = import.meta.glob('./**/*.svelte', {
  query: '?raw',
  import: 'default',
  eager: true,
}) as Record<string, string>;

function settingsTables(): { file: string; classes: string[]; columns: number }[] {
  const tables = [];
  for (const [file, source] of Object.entries(sources)) {
    for (const match of source.matchAll(/<table class="([^"]*)"([\s\S]*?)<\/thead>/g)) {
      const classes = match[1].split(/\s+/);
      if (!classes.includes('settings-table')) continue;
      const columns = match[2].match(/<th[\s>]/g)?.length ?? 0;
      tables.push({ file, classes, columns });
    }
  }
  return tables;
}

describe('settings tables', () => {
  it('finds the fixed column widths and the settings tables it guards', () => {
    expect(FIXED_LAYOUT_COLUMNS).toBeGreaterThan(0);
    expect(settingsTables().length).toBeGreaterThan(0);
  });

  it('opt out of the four-column fixed layout when they have more columns', () => {
    const squeezed = settingsTables()
      .filter((t) => t.columns > FIXED_LAYOUT_COLUMNS && !t.classes.includes('settings-table-wide'))
      .map((t) => `${t.file} (${t.columns} columns)`);
    expect(squeezed).toEqual([]);
  });
});
