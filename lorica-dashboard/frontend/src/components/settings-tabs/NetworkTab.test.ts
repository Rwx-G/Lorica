import { render, screen, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi, afterEach } from 'vitest';
import type { ComponentProps } from 'svelte';

import NetworkTab, { proxyProtocolError, proxyProtocolPayload } from './NetworkTab.svelte';
import { auth } from '../../lib/auth';
import { reactive } from '../../test-reactive.svelte';

type TabProps = ComponentProps<typeof NetworkTab>;
type FormShape = TabProps['settingsForm'];

const FIELD_LABEL = 'Automation Listener Allowed CIDRs';

/// `settingsForm` is `$bindable`, so it has to arrive as a `$state`
/// proxy: a plain object makes the component's writes through the
/// binding unobservable and Svelte warns `binding_property_non_reactive`.
function form(overrides: Partial<FormShape> = {}): FormShape {
  return reactive<FormShape>({
    trusted_proxies: '',
    proxy_protocol_http: 'off',
    proxy_protocol_https: 'off',
    proxy_protocol_trusted_cidrs: '',
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
  });
}

function props(overrides: Partial<TabProps> = {}): TabProps {
  return {
    settingsForm: form(),
    schema: {},
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

const HTTP_MODE = 'HTTP listener';
const HTTPS_MODE = 'HTTPS listener';
const PEERS = 'PROXY Protocol Trusted Peers (CIDR)';

function proxyAlert(): string | null {
  const row = screen.getByLabelText(PEERS).parentElement as HTMLElement;
  return row.querySelector('[role="alert"]')?.textContent ?? null;
}

describe('NetworkTab PROXY protocol', () => {
  afterEach(() => {
    auth.set({ status: 'unauthenticated' });
  });

  it('renders the stored values', () => {
    render(NetworkTab, {
      props: props({
        settingsForm: form({
          proxy_protocol_http: 'optional',
          proxy_protocol_https: 'required',
          proxy_protocol_trusted_cidrs: '10.0.0.0/24\n192.0.2.10',
        }),
      }),
    });
    expect((screen.getByLabelText(HTTP_MODE) as HTMLSelectElement).value).toBe('optional');
    expect((screen.getByLabelText(HTTPS_MODE) as HTMLSelectElement).value).toBe('required');
    expect((screen.getByLabelText(PEERS) as HTMLTextAreaElement).value).toBe('10.0.0.0/24\n192.0.2.10');
    expect(proxyAlert()).toBeNull();
  });

  it('says the values are node-local and not trusted proxies', () => {
    render(NetworkTab, { props: props() });
    const text = (document.body.textContent ?? '').replace(/\s+/g, ' ');
    expect(text).toContain('Node-local: never replicated');
    expect(text).toContain('Not the same as Trusted Proxies');
    expect(text).toContain('apply to connections accepted after the save');
  });

  it('sends the three fields, the list as one entry per line', async () => {
    auth.set({ status: 'authenticated', username: 'admin', role: 'super_admin' });
    const settingsForm = form();
    const onSave = vi.fn();
    render(NetworkTab, { props: props({ settingsForm, onSave }) });
    await fireEvent.input(screen.getByLabelText(PEERS), { target: { value: ' 10.0.0.0/24 \n\n192.0.2.10\n' } });
    await fireEvent.change(screen.getByLabelText(HTTP_MODE), { target: { value: 'optional' } });
    await fireEvent.change(screen.getByLabelText(HTTPS_MODE), { target: { value: 'required' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save Network Settings' }));

    expect(onSave).toHaveBeenCalledOnce();
    expect(proxyProtocolPayload(settingsForm)).toEqual({
      proxy_protocol_http: 'optional',
      proxy_protocol_https: 'required',
      proxy_protocol_trusted_cidrs: ['10.0.0.0/24', '192.0.2.10'],
    });
  });

  it('sends an emptied list as an empty array, so clearing it reaches the server', () => {
    expect(
      proxyProtocolPayload({ proxy_protocol_http: 'off', proxy_protocol_https: 'off', proxy_protocol_trusted_cidrs: '  \n' }),
    ).toEqual({ proxy_protocol_http: 'off', proxy_protocol_https: 'off', proxy_protocol_trusted_cidrs: [] });
  });

  it('shows the server refusal as returned', () => {
    const refusal =
      'proxy_protocol_https is required but proxy_protocol_trusted_cidrs is empty: no peer could send a PROXY header; list the load balancers first, or set proxy_protocol_https to off';
    render(NetworkTab, { props: props({ settingsError: refusal }) });
    expect(screen.getByText(refusal)).toBeInTheDocument();
  });

  it.each(['0.0.0.0/0', '10.0.0.0/0', '::/0', '2001:db8::/0'])('refuses %s, which trusts every address', async (entry) => {
    render(NetworkTab, { props: props() });
    await fireEvent.input(screen.getByLabelText(PEERS), { target: { value: `10.0.0.0/24\n${entry}` } });
    expect(proxyAlert()).toContain(`line 2 (${entry}) trusts every address`);
  });

  it('accepts a bare address, which is a host prefix and not a /0', async () => {
    render(NetworkTab, { props: props() });
    await fireEvent.input(screen.getByLabelText(PEERS), { target: { value: '192.0.2.10\n2001:db8::1' } });
    expect(proxyAlert()).toBeNull();
  });

  it('reports a malformed entry by line, like the other address lists', async () => {
    render(NetworkTab, { props: props() });
    await fireEvent.input(screen.getByLabelText(PEERS), { target: { value: '10.0.0.0/24\nnot-a-cidr' } });
    expect(proxyAlert()).toContain('line 2 (not-a-cidr)');
  });

  it('refuses a listener mode switched on while nobody is trusted', async () => {
    render(NetworkTab, { props: props() });
    await fireEvent.change(screen.getByLabelText(HTTPS_MODE), { target: { value: 'required' } });
    expect(proxyAlert()).toContain('the HTTPS listener is required but no peer is trusted');
    await fireEvent.input(screen.getByLabelText(PEERS), { target: { value: '10.0.0.0/24' } });
    expect(proxyAlert()).toBeNull();
  });

  it('refuses clearing the list while a mode is on', async () => {
    render(NetworkTab, {
      props: props({
        settingsForm: form({ proxy_protocol_http: 'optional', proxy_protocol_trusted_cidrs: '10.0.0.0/24' }),
      }),
    });
    expect(proxyAlert()).toBeNull();
    await fireEvent.input(screen.getByLabelText(PEERS), { target: { value: '' } });
    expect(proxyAlert()).toContain('the HTTP listener is optional but no peer is trusted');
  });

  it('accepts both modes off with an empty list, the default', () => {
    expect(
      proxyProtocolError({ proxy_protocol_http: 'off', proxy_protocol_https: 'off', proxy_protocol_trusted_cidrs: '' }),
    ).toBeNull();
  });
});

describe('NetworkTab defense-in-depth bounds', () => {
  it('takes its bounds from the server schema', async () => {
    // The server publishes what its validator enforces; the tab must
    // refuse what the server would, not a number of its own.
    const schema = { bot_stash_max_entries: { type: 'integer' as const, min: 5, max: 50 } };
    render(NetworkTab, { props: props({ schema }) });
    const field = screen.getByLabelText('Bot challenge stash - max entries') as HTMLInputElement;
    expect(field.min).toBe('5');
    expect(field.max).toBe('50');
    await fireEvent.input(field, { target: { value: '51' } });
    expect(screen.getByRole('alert').textContent).toContain('5..50');
    await fireEvent.input(field, { target: { value: '50' } });
    expect(screen.queryAllByRole('alert')).toHaveLength(0);
  });

  it('accepts 0 as an audit retention, which keeps the trail forever', async () => {
    render(NetworkTab, { props: props() });
    const field = screen.getByLabelText('Audit log retention (days)');
    await fireEvent.input(field, { target: { value: '0' } });
    expect(screen.queryAllByRole('alert')).toHaveLength(0);
    expect(field.parentElement?.textContent).toContain('0 = kept forever');
  });
});
