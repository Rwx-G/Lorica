import { render, screen, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi } from 'vitest';

import { testAuthority } from '../../test-adcs-fixtures';
import { ADCS_KEY_TYPE_LABELS } from '../../lib/adcs.generated';
import AdcsIssueConfirm from './AdcsIssueConfirm.svelte';

function renderConfirm(overrides: Partial<{ submitting: boolean }> = {}) {
  const onconfirm = vi.fn();
  const oncancel = vi.fn();
  render(AdcsIssueConfirm, {
    props: {
      authority: testAuthority(),
      request: {
        sans: ['app.corp.example.org', 'www.app.corp.example.org'],
        key_type: 'rsa3072',
        subject: { organizational_unit: 'Web' },
      },
      onconfirm,
      oncancel,
      ...overrides,
    },
  });
  return { onconfirm, oncancel };
}

describe('AdcsIssueConfirm', () => {
  it('shows the template, key type, complete subject and every SAN', () => {
    renderConfirm();
    expect(screen.getByTestId('adcs-confirm-template')).toHaveTextContent('LoricaWebServer');
    expect(screen.getByTestId('adcs-confirm-key-type')).toHaveTextContent(ADCS_KEY_TYPE_LABELS.rsa3072);
    const subject = screen.getByTestId('adcs-confirm-subject');
    const pairs = [...subject.querySelectorAll('dt')].map((dt) => [
      dt.textContent?.trim(),
      dt.nextElementSibling?.textContent?.trim(),
    ]);
    expect(pairs).toEqual([
      ['Common name (CN)', 'app.corp.example.org'],
      ['Country (C)', 'FR'],
      ['Locality (L)', 'Paris'],
      ['Organization (O)', 'Example Corp'],
      ['Organizational unit (OU)', 'Web'],
    ]);
    const sans = screen.getByTestId('adcs-confirm-sans').querySelectorAll('li');
    expect([...sans].map((li) => li.textContent)).toEqual([
      'app.corp.example.org',
      'www.app.corp.example.org',
    ]);
  });

  it('says the issuance is recorded and only revocation undoes it', () => {
    renderConfirm();
    expect(screen.getByRole('note')).toHaveTextContent('authority records the issuance');
    expect(screen.getByRole('note')).toHaveTextContent('only be undone by revocation');
  });

  it('issues only on an explicit click, never on Enter', async () => {
    const { onconfirm, oncancel } = renderConfirm();
    await fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Enter' });
    expect(onconfirm).not.toHaveBeenCalled();
    await fireEvent.click(screen.getByRole('button', { name: 'Issue' }));
    expect(onconfirm).toHaveBeenCalledOnce();
    await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(oncancel).toHaveBeenCalledOnce();
  });

  it('disables both buttons while the request runs', () => {
    renderConfirm({ submitting: true });
    expect(screen.getByRole('button', { name: 'Issuing...' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
  });

  it('moves focus to Cancel, never to Issue', () => {
    renderConfirm();
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Cancel' }));
  });
});
