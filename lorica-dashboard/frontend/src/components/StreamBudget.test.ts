import { render, screen, within } from '@testing-library/svelte';
import { describe, it, expect } from 'vitest';

import type { NodeStreamBudget, StreamBudgetShare } from '../lib/api';
import StreamBudget from './StreamBudget.svelte';

function share(overrides: Partial<StreamBudgetShare> = {}): StreamBudgetShare {
  return {
    id: 's1',
    name: 'pg',
    protocol: 'tcp',
    listen_sockets: 1,
    ceiling: null,
    fds_per_unit: null,
    fds_committed: 1,
    bind_state: 'bound',
    ...overrides,
  };
}

function budget(overrides: Partial<NodeStreamBudget> = {}): NodeStreamBudget {
  return {
    node_id: null,
    node_name: null,
    reported_at: '2026-11-14T10:00:00Z',
    fd_limit: 65536,
    base_reserve: 1024,
    http_reserve: 32768,
    stream_budget: 31744,
    worker_count: 8,
    listen_socket_cap: 2048,
    listen_sockets_used: 3,
    worker_fds_committed: 3,
    supervisor_fds_committed: 17,
    worker_drain_timeout_s: 30,
    streams: [share()],
    ...overrides,
  };
}

function rowOf(name: string): HTMLElement {
  return screen.getByText(name).closest('tr') as HTMLElement;
}

describe('StreamBudget', () => {
  it('shows the fd limit, both reserves and the stream budget', () => {
    render(StreamBudget, { props: { nodes: [budget()] } });
    expect(screen.getByText('65,536')).toBeInTheDocument();
    expect(screen.getByText('1,024')).toBeInTheDocument();
    expect(screen.getByText('32,768')).toBeInTheDocument();
    // The stream budget is also the denominator of two gauges.
    expect(screen.getAllByText(/31,744/).length).toBeGreaterThan(0);
    expect(screen.getByText('3 / 2,048')).toBeInTheDocument();
  });

  it('renders a null ceiling as a dash whose tooltip names it, never as 0', () => {
    render(StreamBudget, { props: { nodes: [budget()] } });
    const cells = within(rowOf('pg')).getAllByTitle(/No ceiling declared/);
    expect(cells).toHaveLength(2);
    for (const cell of cells) expect(cell.textContent).toBe('-');
    expect(within(rowOf('pg')).queryByText('0')).toBeNull();
  });

  it('shows a declared ceiling as its number', () => {
    render(StreamBudget, {
      props: { nodes: [budget({ streams: [share({ ceiling: 500, fds_per_unit: 2, fds_committed: 1001 })] })] },
    });
    const row = rowOf('pg');
    expect(within(row).getByText('500')).toBeInTheDocument();
    expect(within(row).getByText('1,001')).toBeInTheDocument();
    expect(within(row).queryByTitle(/No ceiling declared/)).toBeNull();
  });

  it('renders each bind state as its shared badge', () => {
    render(StreamBudget, {
      props: {
        nodes: [
          budget({
            streams: [
              share({ id: 'a', name: 'pg', bind_state: 'bound' }),
              share({ id: 'b', name: 'dns', bind_state: 'failed' }),
              share({ id: 'c', name: 'smtp', bind_state: 'unknown' }),
            ],
          }),
        ],
      },
    });
    expect(within(rowOf('pg')).getByText('bound')).toHaveClass('badge', 'badge-green');
    expect(within(rowOf('dns')).getByText('failed')).toHaveClass('badge', 'badge-red');
    expect(within(rowOf('smtp')).getByText('unknown')).toHaveClass('badge', 'badge-gray');
  });

  it('names this node and every reporting node', () => {
    render(StreamBudget, {
      props: { nodes: [budget(), budget({ node_id: 'n1', node_name: 'edge01', streams: [] })] },
    });
    expect(screen.getByRole('heading', { name: 'This node' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'edge01' })).toBeInTheDocument();
    expect(screen.getByText('No stream binds on this node.')).toBeInTheDocument();
  });

  it('says a node whose fd limit could not be read has no stream budget', () => {
    render(StreamBudget, {
      props: { nodes: [budget({ fd_limit: 0, http_reserve: 0, stream_budget: 0 })] },
    });
    expect(screen.getByRole('alert').textContent?.replace(/\s+/g, ' ')).toContain('no stream budget');
  });
});
