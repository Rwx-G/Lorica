import { render, screen } from '@testing-library/svelte';
import { describe, it, expect } from 'vitest';
import CertExpiryBadge from './CertExpiryBadge.svelte';

function daysFromNow(days: number): string {
  const d = new Date();
  d.setDate(d.getDate() + days);
  // Set to end of day so Math.floor gives the expected number of days
  d.setHours(23, 59, 59, 0);
  return d.toISOString();
}

describe('CertExpiryBadge', () => {
  it('renders Valid for certificate expiring in 60 days', () => {
    render(CertExpiryBadge, { props: { notAfter: daysFromNow(60) } });
    expect(screen.getByText('Valid')).toBeInTheDocument();
  });

  it('applies valid CSS class for valid cert', () => {
    const { container } = render(CertExpiryBadge, { props: { notAfter: daysFromNow(60) } });
    expect(container.querySelector('.valid')).not.toBeNull();
  });

  it('renders warning for certificate expiring in 20 days', () => {
    render(CertExpiryBadge, { props: { notAfter: daysFromNow(20) } });
    expect(screen.getByText('20d left')).toBeInTheDocument();
  });

  it('applies warning CSS class', () => {
    const { container } = render(CertExpiryBadge, { props: { notAfter: daysFromNow(20) } });
    expect(container.querySelector('.warning')).not.toBeNull();
  });

  it('renders critical for certificate expiring in 5 days', () => {
    render(CertExpiryBadge, { props: { notAfter: daysFromNow(5) } });
    expect(screen.getByText('5d left')).toBeInTheDocument();
  });

  it('applies critical CSS class', () => {
    const { container } = render(CertExpiryBadge, { props: { notAfter: daysFromNow(5) } });
    expect(container.querySelector('.critical')).not.toBeNull();
  });

  it('renders Expired for past date', () => {
    render(CertExpiryBadge, { props: { notAfter: daysFromNow(-1) } });
    expect(screen.getByText('Expired')).toBeInTheDocument();
  });

  it('applies expired CSS class', () => {
    const { container } = render(CertExpiryBadge, { props: { notAfter: daysFromNow(-1) } });
    expect(container.querySelector('.expired')).not.toBeNull();
  });

  it('respects custom warning threshold', () => {
    render(CertExpiryBadge, { props: { notAfter: daysFromNow(45), warningDays: 60 } });
    expect(screen.getByText('45d left')).toBeInTheDocument();
  });

  it('respects custom critical threshold', () => {
    render(CertExpiryBadge, { props: { notAfter: daysFromNow(12), criticalDays: 14 } });
    expect(screen.getByText('12d left')).toBeInTheDocument();
    const { container } = render(CertExpiryBadge, { props: { notAfter: daysFromNow(12), criticalDays: 14 } });
    expect(container.querySelector('.critical')).not.toBeNull();
  });
});
