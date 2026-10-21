import { render, screen } from '@testing-library/svelte';
import { describe, it, expect, vi } from 'vitest';

import { testCertificate } from '../../test-adcs-fixtures';
import CertificateList from './CertificateList.svelte';
import CertificateDetail from './CertificateDetail.svelte';

describe('certificate source on the list', () => {
  it('shows one badge per source, read from `source`', () => {
    render(CertificateList, {
      props: {
        certificates: [
          testCertificate('acme.corp.example.org', [], { source: 'acme', is_acme: true }),
          testCertificate('adcs.corp.example.org', [], { source: 'adcs', adcs_template: 'LoricaWebServer' }),
          testCertificate('manual.corp.example.org'),
        ],
        routes: [],
        warningDays: 30,
        criticalDays: 7,
        renewingId: '',
        onView: vi.fn(),
        onEdit: vi.fn(),
        onRenew: vi.fn(),
        onDelete: vi.fn(),
        onDownload: vi.fn(),
      },
    });
    const row = (domain: string) => screen.getByRole('button', { name: domain }).closest('td');
    expect(row('acme.corp.example.org')).toHaveTextContent('ACME');
    expect(row('adcs.corp.example.org')).toHaveTextContent('AD CS');
    expect(row('manual.corp.example.org')).toHaveTextContent('Manual');
  });
});

describe('certificate source on the detail view', () => {
  it('shows the AD CS fields for an AD CS certificate', () => {
    render(CertificateDetail, {
      props: {
        detailCert: {
          ...testCertificate('adcs.corp.example.org', [], {
            source: 'adcs',
            acme_auto_renew: true,
            adcs_authority_id: 'adcs-1',
            adcs_template: 'LoricaWebServer',
            adcs_template_oid: '1.3.6.1.4.1.311.21.8.1.2.3',
            adcs_request_id: '4711',
          }),
          cert_pem: '-----BEGIN CERTIFICATE-----',
          associated_routes: [],
        },
        detailLoading: false,
        routes: [],
        warningDays: 30,
        criticalDays: 7,
        onClose: vi.fn(),
      },
    });
    expect(screen.getByTestId('cert-detail-source')).toHaveTextContent('AD CS (auto-renew)');
    expect(screen.getByText('LoricaWebServer')).toBeInTheDocument();
    expect(screen.getByText('1.3.6.1.4.1.311.21.8.1.2.3')).toBeInTheDocument();
    expect(screen.getByText('4711')).toBeInTheDocument();
  });

  it('shows no AD CS fields for a manual certificate', () => {
    render(CertificateDetail, {
      props: {
        detailCert: { ...testCertificate('manual.corp.example.org'), cert_pem: '', associated_routes: [] },
        detailLoading: false,
        routes: [],
        warningDays: 30,
        criticalDays: 7,
        onClose: vi.fn(),
      },
    });
    expect(screen.getByTestId('cert-detail-source')).toHaveTextContent('Manual');
    expect(screen.queryByText('AD CS template')).not.toBeInTheDocument();
  });
});
