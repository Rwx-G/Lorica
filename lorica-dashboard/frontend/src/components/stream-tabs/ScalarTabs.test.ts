import { render } from '@testing-library/svelte';
import type { Component } from 'svelte';
import { describe, it, expect } from 'vitest';

import { FIELD_TAB, SCALAR_SPECS, newDraft, type ScalarField, type StreamField, type StreamTab } from '../../lib/stream-form';
import ConnectionTab from './ConnectionTab.svelte';
import GeneralTab from './GeneralTab.svelte';
import ProtectionTab from './ProtectionTab.svelte';
import TlsTab from './TlsTab.svelte';

/**
 * The tab component that renders each tab's scalar fields; `null` for a
 * tab whose controls are all hand-built (the links, the UDP settings),
 * which no scalar field may be placed on.
 */
const SCALAR_TAB: Record<StreamTab, Component<never> | null> = {
  general: GeneralTab as Component<never>,
  backends: null,
  tls: TlsTab as Component<never>,
  connection: ConnectionTab as Component<never>,
  udp: null,
  protection: ProtectionTab as Component<never>,
};

const EVERY_FIELD: ReadonlySet<StreamField> = new Set(Object.keys(FIELD_TAB) as StreamField[]);
const SCALARS = Object.keys(SCALAR_SPECS) as ScalarField[];

describe('every scalar field is rendered by the tab FIELD_TAB places it on', () => {
  it.each(SCALARS)('%s', (field) => {
    const tab = SCALAR_TAB[FIELD_TAB[field]];
    expect(tab, `${field} is placed on ${FIELD_TAB[field]}, which renders no scalar field`).not.toBeNull();
    const { container } = render(tab as Component<Record<string, unknown>>, {
      props: { draft: newDraft(), fields: EVERY_FIELD, protocol: 'tcp', creating: false, certificates: [] },
    });
    expect(container.querySelector(`#stream-${field}`), field).not.toBeNull();
  });
});
