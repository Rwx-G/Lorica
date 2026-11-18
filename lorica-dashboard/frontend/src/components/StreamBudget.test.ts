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
    usable_source_ports: 27208,
    session_ceiling: 27208,
    session_ceiling_bound_by: 'source_ports',
    udp_sessions_committed: 0,
    over_ceiling: false,
    source_pools: [],
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

describe('StreamBudget, UDP session ceiling (Story 12.5 Lot J)', () => {
  const udpShare = share({ id: 'u1', name: 'dns', protocol: 'udp', ceiling: 4096, fds_per_unit: 1, fds_committed: 4097 });

  function udpBudget(overrides: Partial<NodeStreamBudget> = {}): NodeStreamBudget {
    return budget({
      streams: [share(), udpShare],
      session_ceiling: 27208,
      session_ceiling_bound_by: 'source_ports',
      udp_sessions_committed: 4096,
      source_pools: [{ pool: 'default', committed: 4096, usable: 27208 }],
      ...overrides,
    });
  }

  function text(element: Element | null): string {
    return (element?.textContent ?? '').replace(/\s+/g, ' ');
  }

  it('shows nothing of UDP on a node that holds no UDP stream', () => {
    render(StreamBudget, { props: { nodes: [budget()] } });
    expect(screen.queryByText('UDP sessions')).toBeNull();
    expect(screen.queryByText('Source pool')).toBeNull();
  });

  it('shows the committed sessions against the ceiling, and what bound it', () => {
    render(StreamBudget, { props: { nodes: [udpBudget()] } });
    expect(screen.getByText('4,096 / 27,208')).toBeInTheDocument();
    const line = screen.getByText(/Session ceiling/);
    expect(text(line)).toContain('bound by the usable source ports');
    expect(text(line)).toContain('per source address: 27,208');
  });

  it('names the fd budget when it set the ceiling', () => {
    render(StreamBudget, {
      props: { nodes: [udpBudget({ session_ceiling: 20000, session_ceiling_bound_by: 'fd_budget' })] },
    });
    expect(text(screen.getByText(/Session ceiling/))).toContain('bound by the fd budget');
  });

  it('says the usable ports are unknown when the node did not report them', () => {
    render(StreamBudget, {
      props: {
        nodes: [udpBudget({ usable_source_ports: null, source_pools: [{ pool: 'default', committed: 4096, usable: null }] })],
      },
    });
    expect(screen.getByTitle(/checked on fds alone/)).toHaveTextContent('unknown');
    const pool = screen.getByText('default').closest('tr') as HTMLElement;
    expect(within(pool).getByText('-')).toBeInTheDocument();
  });

  it('lists each source pool with its committed sessions and usable ports', () => {
    render(StreamBudget, {
      props: {
        nodes: [
          udpBudget({
            source_pools: [
              { pool: 'default', committed: 4096, usable: 27208 },
              { pool: '192.0.2.10', committed: 30000, usable: 27208 },
            ],
          }),
        ],
      },
    });
    const crowded = screen.getByText('192.0.2.10').closest('tr') as HTMLElement;
    expect(within(crowded).getByText('30,000')).toBeInTheDocument();
    expect(crowded).toHaveClass('over');
    expect(screen.getByText('default').closest('tr')).not.toHaveClass('over');
  });

  it('warns a node past its ceiling that raising writes are refused and lowering ones pass', () => {
    render(StreamBudget, { props: { nodes: [udpBudget({ over_ceiling: true, session_ceiling: 1000 })] } });
    const alert = text(screen.getByRole('alert'));
    expect(alert).toContain('Past its UDP session ceiling');
    expect(alert).toContain('raises the demand is refused');
    expect(alert).toContain('lowers it passes');
  });

  it("shows a UDP stream's share in its row, titled as its share of the ceiling", () => {
    render(StreamBudget, { props: { nodes: [udpBudget()] } });
    const share = within(rowOf('dns')).getByTitle(/share of the node's session ceiling/);
    expect(share).toHaveTextContent('4,096');
  });
});
