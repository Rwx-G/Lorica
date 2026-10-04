import { render, screen, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi } from 'vitest';
import type { ComponentProps } from 'svelte';

import GlobalConfigTab from './GlobalConfigTab.svelte';
import { reactive } from '../../test-reactive.svelte';

type TabProps = ComponentProps<typeof GlobalConfigTab>;
type FormShape = TabProps['settingsForm'];

/// `settingsForm` is `$bindable`, so it has to arrive as a `$state`
/// proxy (see `test-reactive.svelte.ts`).
function form(overrides: Partial<FormShape> = {}): FormShape {
  return reactive({
    management_port: 9443,
    log_level: 'info',
    default_health_check_interval_s: 10,
    health_max_concurrent_probes: 32,
    cert_warning_days: 30,
    cert_critical_days: 7,
    max_global_connections: 0,
    flood_threshold_rps: 0,
    flood_strict_rps: 0,
    header_timeout_s: 10,
    waf_ban_threshold: 3,
    waf_ban_duration_s: 3600,
    waf_body_scan_max_inflight_bytes: 268435456,
    access_log_retention: 100000,
    waf_event_retention: 100000,
    sla_purge_enabled: false,
    sla_purge_retention_days: 90,
    sla_purge_schedule: 'first_of_month',
    waf_whitelist_ips: '',
    max_active_probes: 50,
    loadtest_max_concurrency: 100,
    loadtest_max_duration_s: 60,
    loadtest_max_rps: 1000,
    ...overrides,
  });
}

function props(overrides: Partial<TabProps> = {}): TabProps {
  return {
    settingsForm: form(),
    schema: {},
    expanded: true,
    toggleSection: vi.fn(),
    settingsSaving: false,
    settingsMsg: '',
    settingsError: '',
    onSave: vi.fn(),
    ...overrides,
  };
}

/// Backlog #89: the settings the form could not write. Each label is
/// paired with the key it edits, so a test can say which one failed.
const ADDED_FIELDS: [string, keyof FormShape][] = [
  ['Flood Strict Rate (RPS per IP)', 'flood_strict_rps'],
  ['Header Timeout (seconds)', 'header_timeout_s'],
  ['Max Active Probes', 'max_active_probes'],
  ['Load Test Concurrency Ceiling', 'loadtest_max_concurrency'],
  ['Load Test Duration Ceiling (seconds)', 'loadtest_max_duration_s'],
  ['Load Test Rate Ceiling (RPS)', 'loadtest_max_rps'],
];

describe('GlobalConfigTab, the settings backlog #89 added', () => {
  it('shows each one, editable, with the stored value', () => {
    const settingsForm = form({
      flood_strict_rps: 40,
      header_timeout_s: 15,
      max_active_probes: 7,
      loadtest_max_concurrency: 250,
      loadtest_max_duration_s: 120,
      loadtest_max_rps: 5000,
    });
    render(GlobalConfigTab, { props: props({ settingsForm }) });
    for (const [label, key] of ADDED_FIELDS) {
      const field = screen.getByLabelText(label) as HTMLInputElement;
      expect(field.disabled, label).toBe(false);
      expect(field.value, label).toBe(String(settingsForm[key]));
    }
  });

  it('writes an edit back into the form', async () => {
    const settingsForm = form();
    render(GlobalConfigTab, { props: props({ settingsForm }) });
    await fireEvent.input(screen.getByLabelText('Max Active Probes'), { target: { value: '12' } });
    expect(settingsForm.max_active_probes).toBe(12);
  });

  it('takes every bound from the server schema', async () => {
    const schema = Object.fromEntries(
      ADDED_FIELDS.map(([, key]) => [key, { type: 'integer' as const, min: 2, max: 9 }]),
    );
    render(GlobalConfigTab, { props: props({ schema }) });
    for (const [label] of ADDED_FIELDS) {
      const field = screen.getByLabelText(label) as HTMLInputElement;
      expect(field.min, label).toBe('2');
      expect(field.max, label).toBe('9');
      await fireEvent.input(field, { target: { value: '10' } });
      const row = field.parentElement as HTMLElement;
      expect(row.querySelector('[role="alert"]')?.textContent, label).toContain('2..9');
      await fireEvent.input(field, { target: { value: '9' } });
      expect(row.querySelector('[role="alert"]'), label).toBeNull();
    }
  });

  it('refuses a strict flood rate at or above the threshold, and accepts 0', async () => {
    // The server's cross-field rule: strict is the tighter cap of the
    // two while both are set; 0 is "auto", half the threshold.
    render(GlobalConfigTab, {
      props: props({ settingsForm: form({ flood_threshold_rps: 100 }) }),
    });
    const strict = screen.getByLabelText('Flood Strict Rate (RPS per IP)');
    const row = strict.parentElement as HTMLElement;
    await fireEvent.input(strict, { target: { value: '100' } });
    expect(row.querySelector('[role="alert"]')?.textContent).toContain('below the flood detection threshold (100)');
    await fireEvent.input(strict, { target: { value: '99' } });
    expect(row.querySelector('[role="alert"]')).toBeNull();
    await fireEvent.input(strict, { target: { value: '0' } });
    expect(row.querySelector('[role="alert"]')).toBeNull();
  });

  it('re-weighs the strict rate when the threshold moves under it', async () => {
    render(GlobalConfigTab, {
      props: props({ settingsForm: form({ flood_threshold_rps: 100, flood_strict_rps: 60 }) }),
    });
    const row = screen.getByLabelText('Flood Strict Rate (RPS per IP)').parentElement as HTMLElement;
    await fireEvent.input(screen.getByLabelText('Flood Detection Threshold (RPS)'), {
      target: { value: '50' },
    });
    expect(row.querySelector('[role="alert"]')?.textContent).toContain('(50)');
  });

  it('states the WAF ban ceiling the schema publishes', () => {
    const schema = { waf_ban_duration_s: { type: 'integer' as const, min: 0, max: 2_592_000 } };
    render(GlobalConfigTab, { props: props({ schema }) });
    const row = screen.getByLabelText('WAF Ban Duration (seconds)').parentElement as HTMLElement;
    expect(row.textContent).toContain('max 30 days');
  });
});
