import { render, screen, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi } from 'vitest';
import type { ComponentProps } from 'svelte';

import LogExportTab from './LogExportTab.svelte';
import { reactive } from '../../test-reactive.svelte';

type TabProps = ComponentProps<typeof LogExportTab>;
type FormShape = TabProps['settingsForm'];

/// `settingsForm` is `$bindable`, so it has to arrive as a `$state`
/// proxy: a plain object makes the component's writes through the
/// binding unobservable and Svelte warns `binding_property_non_reactive`.
function form(overrides: Partial<FormShape> = {}): FormShape {
  return reactive({
    syslog_endpoint: '',
    syslog_transport: 'udp',
    syslog_facility: 16,
    syslog_severity_access: 6,
    syslog_severity_waf: 4,
    syslog_severity_audit: 5,
    syslog_access_enabled: true,
    syslog_waf_enabled: true,
    syslog_audit_enabled: true,
    syslog_capture_enabled: true,
    syslog_tls_ca_pem: '',
    syslog_tls_client_cert_pem: '',
    syslog_tls_client_key_pem: '',
    syslog_extra_sd: '',
    otlp_logs_enabled: false,
    otlp_logs_auth_header: '',
    otlp_logs_access_enabled: true,
    otlp_logs_waf_enabled: true,
    otlp_logs_audit_enabled: true,
    otlp_logs_capture_enabled: true,
    ...overrides,
  });
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

/// Label text of every per-kind toggle, paired with the form field it
/// binds. The four kinds are symmetric on both sinks (backlog #50).
const KIND_TOGGLES: ReadonlyArray<[string, keyof FormShape]> = [
  ['Export access logs', 'syslog_access_enabled'],
  ['Export WAF events', 'syslog_waf_enabled'],
  ['Export audit logs', 'syslog_audit_enabled'],
  ['Export capture records', 'syslog_capture_enabled'],
  ['Export access logs via OTLP', 'otlp_logs_access_enabled'],
  ['Export WAF events via OTLP', 'otlp_logs_waf_enabled'],
  ['Export audit logs via OTLP', 'otlp_logs_audit_enabled'],
  ['Export capture records via OTLP', 'otlp_logs_capture_enabled'],
];

function checkbox(label: string): HTMLInputElement {
  return screen.getByLabelText(label) as HTMLInputElement;
}

describe('LogExportTab per-kind toggles', () => {
  it('renders one checkbox per kind on each sink', () => {
    render(LogExportTab, { props: props() });
    for (const [label] of KIND_TOGGLES) {
      const box = checkbox(label);
      expect(box.type).toBe('checkbox');
      expect(box.checked).toBe(true);
    }
  });

  it('reflects a toggle the server reports as off', () => {
    // Every toggle defaults to on server-side; the form must still be
    // able to show one an operator turned off, on either sink.
    render(LogExportTab, {
      props: props({
        settingsForm: form({
          syslog_capture_enabled: false,
          otlp_logs_audit_enabled: false,
        }),
      }),
    });
    expect(checkbox('Export capture records').checked).toBe(false);
    expect(checkbox('Export audit logs via OTLP').checked).toBe(false);
    // The neighbours are untouched: each kind is its own switch.
    expect(checkbox('Export access logs').checked).toBe(true);
    expect(checkbox('Export capture records via OTLP').checked).toBe(true);
  });

  it('flips a toggle on click', async () => {
    render(LogExportTab, { props: props() });
    const box = checkbox('Export WAF events via OTLP');
    await fireEvent.click(box);
    expect(box.checked).toBe(false);
    await fireEvent.click(box);
    expect(box.checked).toBe(true);
  });
});
