import { render, screen } from '@testing-library/svelte';
import { describe, it, expect } from 'vitest';
import StatusBadge from './StatusBadge.svelte';

describe('StatusBadge', () => {
  it('renders healthy status', () => {
    render(StatusBadge, { props: { status: 'healthy' } });
    expect(screen.getByText('Healthy')).toBeInTheDocument();
  });

  it('renders degraded status', () => {
    render(StatusBadge, { props: { status: 'degraded' } });
    expect(screen.getByText('Degraded')).toBeInTheDocument();
  });

  it('renders down status', () => {
    render(StatusBadge, { props: { status: 'down' } });
    expect(screen.getByText('Down')).toBeInTheDocument();
  });

  it('renders unknown status', () => {
    render(StatusBadge, { props: { status: 'unknown' } });
    expect(screen.getByText('Unknown')).toBeInTheDocument();
  });

  it('applies correct CSS class for healthy', () => {
    const { container } = render(StatusBadge, { props: { status: 'healthy' } });
    expect(container.querySelector('.healthy')).not.toBeNull();
  });

  it('applies correct CSS class for down', () => {
    const { container } = render(StatusBadge, { props: { status: 'down' } });
    expect(container.querySelector('.down')).not.toBeNull();
  });
});
