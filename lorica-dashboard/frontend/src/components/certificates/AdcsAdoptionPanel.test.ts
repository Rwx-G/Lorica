import { render, screen, waitFor, fireEvent, within } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach } from 'vitest';

import { api, type AdcsAdoptionCandidate, type CertificateResponse } from '../../lib/api';
import { testCandidate, testCertificate } from '../../test-adcs-fixtures';
import AdcsAdoptionPanel from './AdcsAdoptionPanel.svelte';

const alpha = testCandidate('alpha.corp.example.org', {
  san_domains: ['alpha.corp.example.org', 'www.alpha.corp.example.org'],
  subject: 'CN=alpha.corp.example.org,OU=IT,O=Example Corp,C=FR',
});
const beta = testCandidate('beta.corp.example.org', {
  issued_template: 'LegacyWebServer',
  observed_template: '1.3.6.1.4.1.311.21.8.1.2',
  template_mismatch: true,
});
const gamma = testCandidate('gamma.corp.example.org', { observed_template: null });

function rendered(candidates: AdcsAdoptionCandidate[] = [alpha, beta, gamma], autoRenewDefault = true) {
  const props = { candidates, autoRenewDefault, onReload: vi.fn().mockResolvedValue(undefined), onClose: vi.fn() };
  render(AdcsAdoptionPanel, { props });
  return props;
}

function candidateBlock(domain: string): HTMLElement {
  const block = screen.getAllByTestId('adcs-adoption-candidate').find((el) => el.textContent?.includes(domain));
  expect(block).toBeDefined();
  return block as HTMLElement;
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('AdcsAdoptionPanel summary', () => {
  it('states that adoption issues nothing and when renewal happens', () => {
    rendered();
    const note = screen.getByTestId('adcs-adoption-note');
    expect(note).toHaveTextContent('Adoption issues nothing');
    expect(note).toHaveTextContent('normal renewal window');
    expect(note).toHaveTextContent('Renew now');
  });

  it('shows the names and subject renewal will request, from the certificate', () => {
    rendered();
    const block = candidateBlock('alpha.corp.example.org');
    expect(block).toHaveTextContent('alpha.corp.example.org, www.alpha.corp.example.org');
    expect(block).toHaveTextContent('CN=alpha.corp.example.org,OU=IT,O=Example Corp,C=FR');
  });

  it('shows both templates and no warning when they match', () => {
    rendered();
    const block = candidateBlock('alpha.corp.example.org');
    expect(within(block).getByTestId('adcs-issued-template')).toHaveTextContent('1.3.6.1.4.1.311.21.8.1.2');
    expect(within(block).getByTestId('adcs-observed-template')).toHaveTextContent('1.3.6.1.4.1.311.21.8.1.2');
    expect(within(block).queryByTestId('adcs-template-mismatch')).not.toBeInTheDocument();
  });

  it('warns when the issued template differs from the observed one', () => {
    rendered();
    const block = candidateBlock('beta.corp.example.org');
    expect(within(block).getByTestId('adcs-issued-template')).toHaveTextContent('LegacyWebServer');
    expect(within(block).getByTestId('adcs-template-mismatch')).toHaveTextContent('different template');
  });

  it('reads "unknown" when Lorica has issued nothing yet', () => {
    rendered();
    const block = candidateBlock('gamma.corp.example.org');
    expect(within(block).getByTestId('adcs-observed-template')).toHaveTextContent(/^unknown$/);
  });

  it('starts every auto-renew checkbox from the authority default', () => {
    rendered([alpha, beta], false);
    expect(screen.getByLabelText('Auto-renew alpha.corp.example.org')).not.toBeChecked();
    expect(screen.getByLabelText('Auto-renew beta.corp.example.org')).not.toBeChecked();
  });
});

describe('AdcsAdoptionPanel adoption', () => {
  it('adopts only the selected certificate, with its auto-renew choice', async () => {
    const adopt = vi.spyOn(api, 'adoptAdcsCertificate').mockResolvedValue({ data: testCertificate('x') });
    const props = rendered();
    await fireEvent.click(screen.getByLabelText('Select beta.corp.example.org'));
    await fireEvent.click(screen.getByLabelText('Auto-renew beta.corp.example.org'));
    await fireEvent.click(screen.getByRole('button', { name: 'Adopt selected (1)' }));
    await waitFor(() => expect(props.onReload).toHaveBeenCalled());
    expect(adopt).toHaveBeenCalledTimes(1);
    expect(adopt).toHaveBeenCalledWith(beta.certificate_id, { auto_renew: false });
  });

  it('adopts every selected certificate one after the other and reports each answer', async () => {
    const order: string[] = [];
    let inFlight = 0;
    vi.spyOn(api, 'adoptAdcsCertificate').mockImplementation(async (id) => {
      inFlight += 1;
      expect(inFlight).toBe(1);
      order.push(id);
      await new Promise((resolve) => setTimeout(resolve, 0));
      inFlight -= 1;
      if (id === beta.certificate_id) {
        return {
          error: {
            code: 'adcs_not_candidate',
            message: 'certificate is not signed by the issuing CA',
            status: 422,
          },
        };
      }
      return { data: testCertificate(id, [], { source: 'adcs' }) as CertificateResponse };
    });
    const props = rendered();
    expect(screen.getByRole('button', { name: 'Adopt selected (0)' })).toBeDisabled();
    await fireEvent.click(screen.getByLabelText('Select all (3)'));
    await fireEvent.click(screen.getByRole('button', { name: 'Adopt selected (3)' }));
    const results = await screen.findByTestId('adcs-adoption-results');
    expect(order).toEqual([alpha.certificate_id, beta.certificate_id, gamma.certificate_id]);
    const items = Array.from(results.querySelectorAll('li'));
    expect(items).toHaveLength(3);
    expect(items[0]).toHaveTextContent('alpha.corp.example.org: Adopted');
    expect(items[1]).toHaveTextContent('beta.corp.example.org: certificate is not signed by the issuing CA');
    expect(items[1]).toHaveAttribute('role', 'alert');
    expect(items[2]).toHaveTextContent('gamma.corp.example.org: Adopted');
    expect(props.onReload).toHaveBeenCalledTimes(1);
  });

  it('clears select all when everything is unselected', async () => {
    rendered([alpha, beta]);
    const all = screen.getByLabelText('Select all (2)');
    await fireEvent.click(all);
    expect(screen.getByLabelText('Select alpha.corp.example.org')).toBeChecked();
    await fireEvent.click(screen.getByLabelText('Select alpha.corp.example.org'));
    expect(all).not.toBeChecked();
    expect(screen.getByRole('button', { name: 'Adopt selected (1)' })).toBeEnabled();
  });
});
