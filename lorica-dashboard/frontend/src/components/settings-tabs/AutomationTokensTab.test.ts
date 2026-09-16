import { render, screen, waitFor, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { auth } from '../../lib/auth';
import { clusterStatus } from '../../lib/cluster';
import { api, type AutomationTokenResponse } from '../../lib/api';
import AutomationTokensTab from './AutomationTokensTab.svelte';

const FULL_TOKEN = '0123456789abcdef01234567.SGVsbG9Xb3JsZFNlY3JldFZhbHVlSGVyZTEyMzQ1Ng';

function token(overrides: Partial<AutomationTokenResponse> = {}): AutomationTokenResponse {
  return {
    public_id: '0123456789abcdef01234567',
    name: 'ci pipeline',
    scopes: ['environments:read', 'environments:write'],
    allowed_hostnames: ['*.preview.example.com'],
    allowed_backend_cidrs: ['10.0.0.0/8'],
    max_ttl_seconds: 604800,
    created_by: 'admin',
    created_at: '2026-01-01T00:00:00Z',
    expires_at: '2027-01-01T00:00:00Z',
    last_used_at: null,
    revoked_at: null,
    ...overrides,
  };
}

function props() {
  return { expanded: true, toggleSection: vi.fn() };
}

beforeEach(() => {
  vi.restoreAllMocks();
  auth.set({ status: 'authenticated', username: 'admin', role: 'super_admin' });
  clusterStatus.set(null);
});

afterEach(() => {
  auth.set({ status: 'unauthenticated' });
  clusterStatus.set(null);
});

describe('AutomationTokensTab listing', () => {
  it('shows the facts an operator retires a token on', async () => {
    vi.spyOn(api, 'listAutomationTokens').mockResolvedValue({
      data: { tokens: [token()] },
    });
    render(AutomationTokensTab, { props: props() });

    await waitFor(() => expect(screen.getByText('ci pipeline')).toBeInTheDocument());
    expect(screen.getByText('0123456789abcdef01234567')).toBeInTheDocument();
    expect(screen.getByText('environments:write')).toBeInTheDocument();
    expect(screen.getByText('*.preview.example.com')).toBeInTheDocument();
    // A token nobody has presented is the one to retire, so "never"
    // has to be rendered rather than left blank.
    expect(screen.getByText('never')).toBeInTheDocument();
  });

  it('badges a revoked token and offers no revoke action on it', async () => {
    vi.spyOn(api, 'listAutomationTokens').mockResolvedValue({
      data: { tokens: [token({ revoked_at: '2026-02-01T00:00:00Z' })] },
    });
    render(AutomationTokensTab, { props: props() });

    await waitFor(() => expect(screen.getByText('Revoked')).toBeInTheDocument());
    expect(screen.queryByRole('button', { name: 'Revoke' })).not.toBeInTheDocument();
  });
});

describe('AutomationTokensTab create-once display', () => {
  async function mintOne(): Promise<void> {
    vi.spyOn(api, 'listAutomationTokens').mockResolvedValue({ data: { tokens: [] } });
    vi.spyOn(api, 'createAutomationToken').mockResolvedValue({
      data: { ...token(), token: FULL_TOKEN },
    });
    render(AutomationTokensTab, { props: props() });

    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Create Token' })).toBeInTheDocument(),
    );
    await fireEvent.click(screen.getByRole('button', { name: 'Create Token' }));
    await fireEvent.input(screen.getByLabelText(/^Name/), { target: { value: 'ci pipeline' } });
    await fireEvent.input(screen.getByLabelText(/^Allowed hostnames/), {
      target: { value: '*.preview.example.com' },
    });
    await fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(screen.getByTestId('minted-token')).toBeInTheDocument());
  }

  it('shows the full token once, with the warning that it will not come back', async () => {
    await mintOne();
    expect(screen.getByTestId('minted-token')).toHaveTextContent(FULL_TOKEN);
    expect(screen.getByRole('alert')).toHaveTextContent(
      /only time this token will be shown/i,
    );
  });

  it('does not send a token field back to the listing after the dialog is dismissed', async () => {
    // The secret is held only between the mint answer and the
    // dismissal. Once dismissed nothing on the page can produce it,
    // which is the invariant the server side guarantees and this side
    // must not quietly break by stashing it on the row.
    await mintOne();
    await fireEvent.click(screen.getByRole('button', { name: 'I have saved it' }));

    await waitFor(() => expect(screen.queryByTestId('minted-token')).not.toBeInTheDocument());
    expect(screen.queryByText(FULL_TOKEN)).not.toBeInTheDocument();
    // The row itself landed in the table, minus the secret.
    expect(screen.getByText('ci pipeline')).toBeInTheDocument();
  });

  it('copies the token to the clipboard on demand', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    });
    await mintOne();
    await fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(FULL_TOKEN));
    expect(screen.getByRole('button', { name: 'Copied' })).toBeInTheDocument();
  });
});

describe('AutomationTokensTab revoke', () => {
  it('asks for confirmation before revoking', async () => {
    vi.spyOn(api, 'listAutomationTokens').mockResolvedValue({ data: { tokens: [token()] } });
    const revoke = vi.spyOn(api, 'revokeAutomationToken');
    render(AutomationTokensTab, { props: props() });

    await waitFor(() => expect(screen.getByRole('button', { name: 'Revoke' })).toBeInTheDocument());
    await fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));

    expect(screen.getByText('Revoke Automation Token')).toBeInTheDocument();
    expect(revoke).not.toHaveBeenCalled();
  });

  it('revokes only after the confirmation is accepted, and badges the row', async () => {
    vi.spyOn(api, 'listAutomationTokens').mockResolvedValue({ data: { tokens: [token()] } });
    const revoke = vi.spyOn(api, 'revokeAutomationToken').mockResolvedValue({
      data: token({ revoked_at: '2026-02-01T00:00:00Z' }),
    });
    render(AutomationTokensTab, { props: props() });

    await waitFor(() => expect(screen.getByRole('button', { name: 'Revoke' })).toBeInTheDocument());
    await fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));
    // The dialog's own confirm button, which carries the same label.
    const buttons = screen.getAllByRole('button', { name: 'Revoke' });
    await fireEvent.click(buttons[buttons.length - 1]);

    await waitFor(() =>
      expect(revoke).toHaveBeenCalledWith('0123456789abcdef01234567'),
    );
    await waitFor(() => expect(screen.getByText('Revoked')).toBeInTheDocument());
  });

  it('leaves the row untouched when the confirmation is cancelled', async () => {
    vi.spyOn(api, 'listAutomationTokens').mockResolvedValue({ data: { tokens: [token()] } });
    const revoke = vi.spyOn(api, 'revokeAutomationToken');
    render(AutomationTokensTab, { props: props() });

    await waitFor(() => expect(screen.getByRole('button', { name: 'Revoke' })).toBeInTheDocument());
    await fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    await waitFor(() =>
      expect(screen.queryByText('Revoke Automation Token')).not.toBeInTheDocument(),
    );
    expect(revoke).not.toHaveBeenCalled();
    expect(screen.queryByText('Revoked')).not.toBeInTheDocument();
  });
});

describe('AutomationTokensTab role gating', () => {
  it('offers no mutation below SuperAdmin', async () => {
    // The server refuses every verb on these paths below SuperAdmin.
    // The dashboard mirrors that rather than rendering a control the
    // node would answer with a 403.
    auth.set({ status: 'authenticated', username: 'op', role: 'operator' });
    vi.spyOn(api, 'listAutomationTokens').mockResolvedValue({ data: { tokens: [token()] } });
    render(AutomationTokensTab, { props: props() });

    await waitFor(() => expect(screen.getByText('ci pipeline')).toBeInTheDocument());
    expect(screen.queryByRole('button', { name: 'Create Token' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Revoke' })).not.toBeInTheDocument();
  });
});
