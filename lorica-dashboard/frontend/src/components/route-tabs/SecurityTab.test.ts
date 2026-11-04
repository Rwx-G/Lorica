import { render, screen, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach } from 'vitest';

import { api } from '../../lib/api';
import {
  ROUTE_DEFAULTS,
  formStateToCreateRequest,
  formStateToUpdateRequest,
  type RouteFormState,
} from '../../lib/route-form';
import { reactive } from '../../test-reactive.svelte';
import SecurityTab from './SecurityTab.svelte';

const PEM = '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n';

function routeForm(): RouteFormState {
  return reactive({ ...ROUTE_DEFAULTS, mtls_ca_cert_pem: PEM });
}

function validated(warnings: string[]) {
  return vi.spyOn(api, 'validateMtlsPem').mockResolvedValue({
    data: { ca_count: 2, subjects: ['CN=Issuing A', 'CN=Root'], warnings },
  });
}

async function validate(): Promise<void> {
  render(SecurityTab, { props: { form: routeForm() } });
  await fireEvent.click(screen.getByRole('button', { name: 'Validate PEM' }));
  await screen.findByText(/2 CA certs parsed/);
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('SecurityTab path matching', () => {
  it('binds the case-insensitive paths checkbox to the form and sends it', async () => {
    const form = routeForm();
    render(SecurityTab, { props: { form } });
    const box = screen.getByRole('checkbox', {
      name: 'Backend treats paths case-insensitively',
    }) as HTMLInputElement;
    expect(box.checked).toBe(false);
    expect(screen.getByText(/IIS, a case-insensitive file system/)).toBeInTheDocument();

    await fireEvent.click(box);
    expect(form.case_insensitive_paths).toBe(true);
    expect(formStateToUpdateRequest(form).case_insensitive_paths).toBe(true);
    expect(formStateToCreateRequest(form).case_insensitive_paths).toBe(true);

    await fireEvent.click(box);
    expect(formStateToUpdateRequest(form).case_insensitive_paths).toBe(false);
  });
});

describe('SecurityTab Validate PEM', () => {
  it('shows each trust warning the API returns', async () => {
    const warning = 'CN=Root is a self-signed root: every CA it signed is trusted on this route.';
    validated([warning]);
    await validate();
    const banner = screen.getByTestId('mtls-bundle-warnings');
    expect(banner).toHaveTextContent(warning);
    expect(banner).toHaveTextContent('The bundle is accepted as it is.');
  });

  it('shows no warning banner for a bundle the API has no warning about', async () => {
    validated([]);
    await validate();
    expect(screen.queryByTestId('mtls-bundle-warnings')).not.toBeInTheDocument();
  });
});
