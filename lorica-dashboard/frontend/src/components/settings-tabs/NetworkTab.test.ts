import { render, screen, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi } from 'vitest';
import type { ComponentProps } from 'svelte';

import NetworkTab from './NetworkTab.svelte';

type TabProps = ComponentProps<typeof NetworkTab>;
type FormShape = TabProps['settingsForm'];

const FIELD_LABEL = 'Automation Listener Allowed CIDRs';

function form(overrides: Partial<FormShape> = {}): FormShape {
  return {
    trusted_proxies: '',
    connection_deny_cidrs: '',
    connection_allow_cidrs: '',
    automation_allowed_cidrs: '',
    geoip_db_path: '',
    geoip_auto_update_enabled: false,
    asn_db_path: '',
    asn_auto_update_enabled: false,
    audit_log_retention_days: 90,
    connection_limits_per_ip: '',
    bot_stash_max_entries: 10000,
    bot_stash_per_prefix_max: 100,
    mirror_max_concurrent_per_route: 32,
    mirror_max_concurrent_global: 4096,
    ...overrides,
  };
}

function props(overrides: Partial<TabProps> = {}): TabProps {
  return {
    settingsForm: form(),
    expanded: true,
    toggleSection: vi.fn(),
    onSave: vi.fn(),
    settingsSaving: false,
    settingsMsg: '',
    settingsError: '',
    ...overrides,
  };
}

/// The rendered hint, with its source line breaks and indentation
/// collapsed, so the assertions read the words and not the wrapping.
function hintText(): string {
  const row = screen.getByLabelText(FIELD_LABEL).parentElement;
  return (row?.textContent ?? '').replace(/\s+/g, ' ').trim();
}

describe('NetworkTab automation allowlist', () => {
  it('renders the automation allowlist field', () => {
    render(NetworkTab, { props: props() });
    expect(screen.getByLabelText(FIELD_LABEL)).toBeInTheDocument();
  });

  it('says the listener stays shut while the list is empty', () => {
    // The field is the switch that opens the plane, not a hardening
    // knob on a plane already open. An operator who reads it the other
    // way configures a listener that never binds and has nothing on
    // screen telling them why.
    render(NetworkTab, { props: props() });
    expect(hintText()).toContain('does not open at all while this is empty');
  });

  it('says the match happens before the TLS handshake', () => {
    // It is evaluated on the connection, not on the request, so a
    // source outside the list never reaches the bearer check and never
    // sees a 401.
    render(NetworkTab, { props: props() });
    expect(hintText()).toContain('before the TLS handshake');
  });

  it('shows the current value', () => {
    render(NetworkTab, {
      props: props({ settingsForm: form({ automation_allowed_cidrs: '10.0.0.0/8\n192.0.2.10' }) }),
    });
    const field = screen.getByLabelText(FIELD_LABEL) as HTMLTextAreaElement;
    expect(field.value).toBe('10.0.0.0/8\n192.0.2.10');
  });

  it('reports the offending line on a bad entry, like the other CIDR fields', async () => {
    render(NetworkTab, { props: props() });
    await fireEvent.input(screen.getByLabelText(FIELD_LABEL), {
      target: { value: '10.0.0.0/8\nnot-a-cidr' },
    });
    const errors = screen.getAllByRole('alert');
    expect(errors.some((e) => e.textContent?.includes('line 2 (not-a-cidr)'))).toBe(true);
  });

  it('clears the error once every entry parses', async () => {
    render(NetworkTab, { props: props() });
    const field = screen.getByLabelText(FIELD_LABEL);
    await fireEvent.input(field, { target: { value: 'not-a-cidr' } });
    expect(screen.queryAllByRole('alert')).not.toHaveLength(0);
    await fireEvent.input(field, { target: { value: '192.0.2.0/24' } });
    expect(screen.queryAllByRole('alert')).toHaveLength(0);
  });
});
