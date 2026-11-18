<script lang="ts">
  import type { NodeStreamBudget } from '../lib/api';
  import { gaugePercent } from '../lib/cluster';
  import { BIND_STATE_BADGE } from '../lib/streams';

  interface Props {
    /** `GET /api/v1/streams/budget`: this node first, then every reporting node by name. */
    nodes: NodeStreamBudget[];
  }

  let { nodes }: Props = $props();

  const NO_CEILING =
    'No ceiling declared: the stream engine declares none yet, so the stream counts only its listening sockets.';

  const UDP_SHARE = "This UDP stream's share of the node's session ceiling (udp.max_sessions).";

  /** What set a node's UDP session ceiling, keyed by the API's word so a new one is a type error here. */
  const BOUND_BY: Record<NodeStreamBudget['session_ceiling_bound_by'], string> = {
    fd_budget: 'the fd budget',
    source_ports: 'the usable source ports',
  };

  /** A node shows its UDP figures once a UDP stream counts on it, or when it is past them. */
  function carriesUdp(node: NodeStreamBudget): boolean {
    return node.over_ceiling || node.udp_sessions_committed > 0 || node.streams.some((s) => s.protocol === 'udp');
  }

  function count(n: number): string {
    return n.toLocaleString('en-US');
  }

  function gaugeColor(percent: number | null): string {
    if (percent === null) return 'var(--color-border)';
    if (percent >= 90) return 'var(--color-red)';
    if (percent >= 70) return 'var(--color-orange)';
    return 'var(--color-green)';
  }

  function usage(node: NodeStreamBudget) {
    return [
      {
        label: 'Listening sockets',
        used: node.listen_sockets_used,
        total: node.listen_socket_cap,
        of: 'the node cap (stream_listen_socket_cap)',
      },
      {
        label: 'One worker',
        used: node.worker_fds_committed,
        total: node.stream_budget,
        of: 'the stream budget, every stream at its ceiling',
      },
      {
        label: 'Supervisor',
        used: node.supervisor_fds_committed,
        total: node.stream_budget,
        of: `the stream budget: TCP ports, plus UDP ports x ${node.worker_count} workers`,
      },
    ];
  }
</script>

<div class="stream-budget">
  <p class="intro">
    Half of each process's fd limit is held back for HTTP and never used by
    streams. A stream write that would break a node's budget is refused; raise
    <code>LimitNOFILE</code> to grow both halves.
  </p>

  {#each nodes as node (node.node_id ?? '')}
    <section class="budget-node" aria-label="Stream budget of {node.node_name ?? 'this node'}">
      <header class="budget-header">
        <h3>{node.node_name ?? 'This node'}</h3>
        <span class="reported" title={node.reported_at}>as of {node.reported_at}</span>
      </header>

      {#if node.fd_limit === 0}
        <p class="warn-text" role="alert">
          The fd limit could not be read on this node, which leaves it no stream
          budget: every stream it should bind is refused.
        </p>
      {/if}

      <dl class="figures">
        <dt>Fd limit</dt>
        <dd>{count(node.fd_limit)}</dd>
        <dt>Base reserve</dt>
        <dd>{count(node.base_reserve)}</dd>
        <dt>HTTP reserve</dt>
        <dd>{count(node.http_reserve)}</dd>
        <dt>Stream budget</dt>
        <dd>{count(node.stream_budget)}</dd>
        <dt>Workers</dt>
        <dd>{node.worker_count}</dd>
        <dt>Drain timeout</dt>
        <dd>{node.worker_drain_timeout_s} s</dd>
      </dl>

      {#each usage(node) as gauge (gauge.label)}
        {@const percent = gaugePercent(gauge.used, gauge.total)}
        <div class="gauge">
          <span class="gauge-label">{gauge.label}</span>
          <div class="gauge-track">
            <div class="gauge-fill" style="width: {percent ?? 0}%; background: {gaugeColor(percent)}"></div>
          </div>
          <span class="gauge-value" title="Against {gauge.of}">
            {count(gauge.used)} / {count(gauge.total)}
          </span>
        </div>
      {/each}

      {#if carriesUdp(node)}
        {@const percent = gaugePercent(node.udp_sessions_committed, node.session_ceiling)}
        <div class="udp-block" aria-label="UDP sessions of {node.node_name ?? 'this node'}">
          {#if node.over_ceiling}
            <p class="warn-text" role="alert">
              Past its UDP session ceiling: the committed sessions, or a source pool's,
              no longer fit, as a narrowed port range or a lowered fd limit leaves a node.
              Bound streams stay bound; a stream write that raises the demand is refused
              until it fits again, one that lowers it passes.
            </p>
          {/if}
          <div class="gauge">
            <span class="gauge-label">UDP sessions</span>
            <div class="gauge-track">
              <div class="gauge-fill" style="width: {Math.min(percent ?? 0, 100)}%; background: {gaugeColor(percent)}"></div>
            </div>
            <span class="gauge-value" title="The UDP streams' shares against the node's session ceiling">
              {count(node.udp_sessions_committed)} / {count(node.session_ceiling)}
            </span>
          </div>
          <p class="ceiling-line">
            Session ceiling {count(node.session_ceiling)}, bound by
            <strong>{BOUND_BY[node.session_ceiling_bound_by]}</strong>.
            Usable source ports per source address:
            {#if node.usable_source_ports === null}
              <span title="The node could not read its port range or has not reported it: its writes are checked on fds alone.">unknown</span>
            {:else}
              {count(node.usable_source_ports)}
            {/if}
          </p>
          {#if node.source_pools.length > 0}
            <table class="share-table pool-table">
              <thead>
                <tr>
                  <th>Source pool</th>
                  <th class="num">Committed sessions</th>
                  <th class="num">Usable ports</th>
                </tr>
              </thead>
              <tbody>
                {#each node.source_pools as pool (pool.pool)}
                  <tr class:over={pool.usable !== null && pool.committed > pool.usable}>
                    <td class="mono">{pool.pool}</td>
                    <td class="num">{count(pool.committed)}</td>
                    <td class="num">{pool.usable === null ? '-' : count(pool.usable)}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
        </div>
      {/if}

      {#if node.streams.length === 0}
        <p class="muted">No stream binds on this node.</p>
      {:else}
        <table class="share-table">
          <thead>
            <tr>
              <th>Stream</th>
              <th>Protocol</th>
              <th class="num">Listening sockets</th>
              <th class="num">Ceiling</th>
              <th class="num">Fds per unit</th>
              <th class="num">Fds committed</th>
              <th>State</th>
            </tr>
          </thead>
          <tbody>
            {#each node.streams as share (share.id)}
              <tr>
                <td>{share.name}</td>
                <td>{share.protocol.toUpperCase()}</td>
                <td class="num">{count(share.listen_sockets)}</td>
                <td class="num">
                  {#if share.ceiling === null}
                    <span class="none" title={NO_CEILING}>-</span>
                  {:else if share.protocol === 'udp'}
                    <span title={UDP_SHARE}>{count(share.ceiling)}</span>
                  {:else}
                    {count(share.ceiling)}
                  {/if}
                </td>
                <td class="num">
                  {#if share.fds_per_unit === null}
                    <span class="none" title={NO_CEILING}>-</span>
                  {:else}
                    {count(share.fds_per_unit)}
                  {/if}
                </td>
                <td class="num">{count(share.fds_committed)}</td>
                <td><span class="badge {BIND_STATE_BADGE[share.bind_state]}">{share.bind_state}</span></td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>
  {/each}
</div>

<style>
  .intro {
    color: var(--color-text-muted);
    font-size: 0.875rem;
    margin: 0 0 var(--space-4);
  }
  .budget-node {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: 0.75rem;
    padding: 1.25rem;
    margin-bottom: var(--space-4);
  }
  .budget-header {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: var(--space-3);
    flex-wrap: wrap;
  }
  .budget-header h3 {
    margin: 0;
    font-size: 1rem;
    color: var(--color-text-heading);
  }
  .reported {
    font-size: 0.75rem;
    color: var(--color-text-muted);
  }
  .figures {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(9rem, 1fr));
    gap: var(--space-2) var(--space-4);
    margin: var(--space-3) 0;
  }
  .figures dt {
    font-size: 0.75rem;
    color: var(--color-text-muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .figures dd {
    margin: 0;
    font-weight: 600;
    font-variant-numeric: tabular-nums;
  }
  .gauge {
    display: grid;
    grid-template-columns: 9rem 1fr auto;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    margin-bottom: 0.35rem;
  }
  .gauge-label {
    color: var(--color-text-muted);
  }
  .gauge-track {
    height: 0.5rem;
    border-radius: 9999px;
    background: var(--color-bg-input);
    overflow: hidden;
  }
  .gauge-fill {
    height: 100%;
    border-radius: 9999px;
  }
  .gauge-value {
    font-variant-numeric: tabular-nums;
  }
  .share-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.875rem;
    margin-top: var(--space-3);
  }
  .share-table th,
  .share-table td {
    padding: 0.4rem 0.75rem 0.4rem 0;
    text-align: left;
    border-bottom: 1px solid var(--color-border);
  }
  .share-table th {
    color: var(--color-text-muted);
    font-weight: 500;
  }
  .share-table .num {
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
  .none {
    color: var(--color-text-muted);
    cursor: help;
  }
  .muted {
    color: var(--color-text-muted);
    margin: var(--space-3) 0 0;
  }
  .warn-text {
    color: var(--color-orange-text);
  }
  .udp-block {
    margin-top: var(--space-3);
  }
  .ceiling-line {
    font-size: 0.8125rem;
    color: var(--color-text-muted);
    margin: var(--space-2) 0;
  }
  .ceiling-line strong {
    color: var(--color-text);
  }
  .pool-table tr.over td {
    color: var(--color-orange-text);
  }
  @media (max-width: 640px) {
    .share-table {
      display: block;
      overflow-x: auto;
    }
  }
</style>
