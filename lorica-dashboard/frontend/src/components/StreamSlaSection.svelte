<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import {
    api,
    type StreamSlaBucket,
    type StreamSlaConfig,
    type StreamSlaSummary,
    type StreamStatus,
    type UpdateStreamSlaConfigRequest,
  } from '../lib/api';
  import { canWrite } from '../lib/auth';
  import { modalFocus } from '../lib/modal-focus';

  interface Props {
    /** The stream a link opened the page on, `''` for none. */
    initialStreamId?: string;
    /**
     * A follower's node id to read that node's own figures, or none for
     * this node's. The target is changed, and the export and the clear
     * act, on this node only, as the route section does.
     */
    node?: string;
  }

  let { initialStreamId = '', node }: Props = $props();

  const REFRESH_MS = 30_000;

  let overview: StreamSlaSummary[] = $state([]);
  let streams: StreamStatus[] = $state([]);
  let error = $state('');
  let loading = $state(true);

  let selectedId = $state('');
  let windows: StreamSlaSummary[] = $state([]);
  let buckets: StreamSlaBucket[] = $state([]);
  let config: StreamSlaConfig | null = $state(null);
  let detailError = $state('');

  let showConfig = $state(false);
  // A number input binds a number, or null while empty.
  let cfgTarget = $state<number | null>(null);
  let cfgLatency = $state<number | null>(null);
  let cfgSaving = $state(false);
  let cfgError = $state('');

  let showClear = $state(false);
  let clearing = $state(false);

  /**
   * One card per stream, its 24 h row: the overview answers two windows
   * per stream, and the detail shows all four.
   */
  const cards = $derived(overview.filter((s) => s.window === '24h'));
  const selected = $derived(streams.find((s) => s.id === selectedId) ?? null);
  /** A UDP stream has no connect: no latency column, no latency bound. */
  const measuresConnect = $derived(selected?.protocol !== 'udp');

  function nameOf(id: string): string {
    return streams.find((s) => s.id === id)?.name ?? id;
  }

  function protocolOf(id: string): string {
    return streams.find((s) => s.id === id)?.protocol ?? '';
  }

  /**
   * The node the figures on screen were read from, `undefined` for this
   * node. Configure, Export and Clear SLA act on this node's store, so
   * they follow the figures shown rather than the picker.
   */
  let figuresNode = $state<string | undefined>(undefined);

  /**
   * Bumped by every overview read, and by every detail read. A node
   * switch overlaps the 30 s refresh and a selection, and a response
   * that is no longer the latest would put the previous node's figures
   * under the new one's name.
   */
  let latestOverviewLoad = 0;
  let latestDetailLoad = 0;

  async function loadOverview() {
    const load = ++latestOverviewLoad;
    const [overviewRes, statusRes] = await Promise.all([
      api.getStreamSlaOverview(node),
      api.getStreamStatus(),
    ]);
    if (load !== latestOverviewLoad) return;
    if (overviewRes.data) overview = overviewRes.data;
    if (statusRes.data) streams = statusRes.data.streams;
    error = overviewRes.error?.message ?? '';
    loading = false;
  }

  async function select(id: string) {
    const load = ++latestDetailLoad;
    const requested = node;
    selectedId = id;
    detailError = '';
    const [windowsRes, bucketsRes, configRes] = await Promise.all([
      api.getStreamSla(id, requested),
      api.getStreamSlaBuckets(id, { node: requested }),
      // Replicated fleet policy: this node's copy is the follower's.
      api.getStreamSlaConfig(id),
    ]);
    if (load !== latestDetailLoad) return;
    windows = windowsRes.data ?? [];
    buckets = bucketsRes.data ?? [];
    config = configRes.data ?? null;
    figuresNode = requested;
    detailError = windowsRes.error?.message ?? '';
  }

  async function refresh() {
    await loadOverview();
    if (selectedId) await select(selectedId);
  }

  // The first run is the first load; a later one is the node picker
  // moving, which re-reads the open stream on the node picked. The
  // figures on screen belong to the previous node, so they go before
  // the read rather than sitting under the new node's name until it
  // lands.
  $effect(() => {
    const picked = node;
    untrack(() => {
      overview = [];
      windows = [];
      buckets = [];
      figuresNode = picked;
      error = '';
      detailError = '';
      loading = true;
      void refresh();
    });
  });

  onMount(() => {
    if (initialStreamId) void select(initialStreamId);
    const timer = setInterval(() => void refresh(), REFRESH_MS);
    return () => clearInterval(timer);
  });

  function openConfig() {
    if (!config) return;
    cfgTarget = config.target_pct;
    cfgLatency = config.max_connect_latency_ms;
    cfgError = '';
    showConfig = true;
  }

  /**
   * The body of a target change: the fields typed, the latency bound only
   * where the stream connects. The server holds the ranges and its
   * refusal is shown as it words it.
   */
  function configBody(): UpdateStreamSlaConfigRequest {
    const body: UpdateStreamSlaConfigRequest = {};
    if (cfgTarget !== null) body.target_pct = cfgTarget;
    if (measuresConnect && cfgLatency !== null) body.max_connect_latency_ms = cfgLatency;
    return body;
  }

  async function saveConfig() {
    cfgSaving = true;
    const res = await api.updateStreamSlaConfig(selectedId, configBody());
    cfgSaving = false;
    if (res.error) {
      cfgError = res.error.message;
    } else if (res.data) {
      config = res.data;
      showConfig = false;
      await refresh();
    }
  }

  async function exportData(format: 'json' | 'csv') {
    const res = await api.exportStreamSla(selectedId, format);
    if (!res.ok) {
      detailError = `Export failed (${res.status})`;
      return;
    }
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement('a');
    a.href = url;
    a.download = `sla-stream-${selectedId}.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function clearData() {
    clearing = true;
    const res = await api.clearStreamSla(selectedId);
    clearing = false;
    showClear = false;
    if (res.error) {
      detailError = res.error.message;
    } else {
      await refresh();
    }
  }

  function pct(s: StreamSlaSummary): string {
    return s.judged_count > 0 ? `${s.sla_pct.toFixed(2)}%` : 'No data';
  }

  function ms(value: number | null): string {
    return value === null ? '-' : `${Math.round(value)} ms`;
  }

  function slaColor(s: StreamSlaSummary): string {
    if (s.judged_count === 0) return 'var(--color-text-muted)';
    if (s.meets_target) return 'var(--color-green)';
    if (s.sla_pct >= s.target_pct - 1) return 'var(--color-orange)';
    return 'var(--color-red)';
  }

  function bucketLatency(b: StreamSlaBucket): string {
    if (b.connected_count === 0 || b.connect_latency_sum_ms === null) return '-';
    return `${Math.round(b.connect_latency_sum_ms / b.connected_count)} ms`;
  }

  function bucketTime(ts: string): string {
    return new Date(ts).toLocaleString([], { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
  }
</script>

<section class="stream-sla" aria-labelledby="stream-sla-title">
  <h2 id="stream-sla-title">Streams</h2>
  <p class="text-muted intro">
    A stream judges connections, not bytes: a TCP connection succeeds when it
    connects to a backend within the latency bound, a UDP session when its
    backend answers. UDP is availability only.
    {node ? "These are the picked node's own figures." : "These are this node's figures."}
  </p>

  {#if error}
    <div class="error-banner" role="alert">{error}</div>
  {/if}

  {#if loading}
    <p class="loading">Loading stream SLA data...</p>
  {:else}
    <div class="overview-grid">
      {#each cards as s (s.stream_id)}
        <button class="sla-card" class:selected={selectedId === s.stream_id} onclick={() => void select(s.stream_id)}>
          <div class="sla-card-header">
            <span class="sla-name">{nameOf(s.stream_id)}</span>
            <span class="sla-window">{protocolOf(s.stream_id).toUpperCase()} 24h</span>
          </div>
          <div class="sla-pct" style="color: {slaColor(s)}">{pct(s)}</div>
          <div class="sla-meta">
            <span>{s.judged_count.toLocaleString()} judged</span>
            {#if s.avg_connect_latency_ms !== null}<span>{ms(s.avg_connect_latency_ms)} avg connect</span>{/if}
            {#if s.judged_count > 0}
              <span class="badge {s.meets_target ? 'badge-green' : 'badge-red'}">{s.meets_target ? 'meets target' : 'breached'}</span>
            {/if}
          </div>
        </button>
      {/each}
      {#if cards.length === 0}
        <p class="text-muted">No stream with SLA data or a target yet.</p>
      {/if}
    </div>

    {#if selectedId}
      <div class="detail-section" aria-label="Stream SLA of {nameOf(selectedId)}">
        <div class="detail-header">
          <h3>{nameOf(selectedId)}</h3>
          <div class="detail-actions">
            {#if figuresNode === undefined}
              {#if $canWrite}
                <button class="btn btn-secondary" onclick={openConfig} disabled={!config}>Configure</button>
              {/if}
              <button class="btn btn-secondary" onclick={() => void exportData('csv')}>Export CSV</button>
              <button class="btn btn-secondary" onclick={() => void exportData('json')}>Export JSON</button>
              {#if $canWrite}
                <button class="btn btn-danger" onclick={() => (showClear = true)}>Clear SLA</button>
              {/if}
            {/if}
          </div>
        </div>

        {#if detailError}
          <div class="error-banner" role="alert">{detailError}</div>
        {/if}

        {#if windows.length > 0}
          <div class="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Window</th>
                  <th class="num">Availability</th>
                  <th class="num">Judged</th>
                  <th class="num">Failures</th>
                  {#if measuresConnect}
                    <th class="num">Avg connect</th>
                    <th class="num">p50</th>
                    <th class="num">p95</th>
                    <th class="num">p99</th>
                  {/if}
                  <th class="num">Target</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {#each windows as s (s.window)}
                  <tr>
                    <td>{s.window}</td>
                    <td class="num" style="color: {slaColor(s)}; font-weight: 600">{s.judged_count > 0 ? `${s.sla_pct.toFixed(2)}%` : '-'}</td>
                    <td class="num">{s.judged_count.toLocaleString()}</td>
                    <td class="num">{s.failure_count.toLocaleString()}</td>
                    {#if measuresConnect}
                      <td class="num">{ms(s.avg_connect_latency_ms)}</td>
                      <td class="num">{ms(s.p50_connect_latency_ms)}</td>
                      <td class="num">{ms(s.p95_connect_latency_ms)}</td>
                      <td class="num">{ms(s.p99_connect_latency_ms)}</td>
                    {/if}
                    <td class="num">{s.target_pct}%</td>
                    <td>
                      {#if s.judged_count === 0}
                        <span class="text-muted">-</span>
                      {:else}
                        <span class="badge {s.meets_target ? 'badge-green' : 'badge-red'}">{s.meets_target ? 'meets target' : 'breached'}</span>
                      {/if}
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}

        {#if config}
          <div class="config-info">
            <span>Target: <strong>{config.target_pct}%</strong></span>
            {#if measuresConnect}
              <span>Max connect latency: <strong>{config.max_connect_latency_ms} ms</strong></span>
            {/if}
          </div>
        {/if}

        {#if buckets.length > 0}
          <h4>Recent minutes (last 24h)</h4>
          <div class="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th class="num">Judged</th>
                  <th class="num">Success</th>
                  <th class="num">Failures</th>
                  {#if measuresConnect}<th class="num">Avg connect</th><th class="num">p95</th>{/if}
                </tr>
              </thead>
              <tbody>
                {#each [...buckets].reverse().slice(0, 30) as b (b.bucket_start)}
                  <tr>
                    <td class="mono">{bucketTime(b.bucket_start)}</td>
                    <td class="num">{b.judged_count}</td>
                    <td class="num">{b.success_count}</td>
                    <td class="num">{b.failure_count}</td>
                    {#if measuresConnect}
                      <td class="num">{bucketLatency(b)}</td>
                      <td class="num">{ms(b.connect_latency_p95_ms)}</td>
                    {/if}
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      </div>
    {/if}
  {/if}

  {#if showConfig}
    <div
      class="overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="stream-sla-config-title"
      tabindex="-1"
      {@attach modalFocus}
      onclick={(e) => { if (e.target === e.currentTarget) showConfig = false; }}
      onkeydown={(e) => { if (e.key === 'Escape') showConfig = false; }}
    >
      <div class="modal">
        <h2 id="stream-sla-config-title">Stream SLA target</h2>
        <div class="form-group">
          <label for="stream-sla-target">Target availability (%)</label>
          <input id="stream-sla-target" type="number" step="any" bind:value={cfgTarget} />
        </div>
        {#if measuresConnect}
          <div class="form-group">
            <label for="stream-sla-latency">Max connect latency (ms)</label>
            <input id="stream-sla-latency" type="number" bind:value={cfgLatency} />
            <span class="hint">A connection that connects slower than this counts as a failure.</span>
          </div>
        {/if}
        {#if cfgError}
          <p class="field-error" role="alert">{cfgError}</p>
        {/if}
        <div class="form-actions">
          <button class="btn btn-cancel" onclick={() => (showConfig = false)}>Cancel</button>
          <button class="btn btn-primary" onclick={() => void saveConfig()} disabled={cfgSaving}>
            {cfgSaving ? 'Saving...' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  {/if}

  {#if showClear}
    <div
      class="overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="stream-sla-clear-title"
      tabindex="-1"
      {@attach modalFocus}
      onclick={(e) => { if (e.target === e.currentTarget) showClear = false; }}
      onkeydown={(e) => { if (e.key === 'Escape') showClear = false; }}
    >
      <div class="modal">
        <h2 id="stream-sla-clear-title">Clear Stream SLA Data</h2>
        <p>This will permanently delete the SLA history of <strong>{nameOf(selectedId)}</strong> on this node.</p>
        <p class="text-muted">This action cannot be undone.</p>
        <div class="form-actions">
          <button class="btn btn-cancel" data-autofocus onclick={() => (showClear = false)}>Cancel</button>
          <button class="btn btn-danger" onclick={() => void clearData()} disabled={clearing}>
            {clearing ? 'Clearing...' : 'Clear all data'}
          </button>
        </div>
      </div>
    </div>
  {/if}
</section>

<style>
  .stream-sla {
    margin-top: var(--space-8);
    border-top: 1px solid var(--color-border);
    padding-top: var(--space-6);
  }
  .stream-sla h2 {
    margin: 0 0 var(--space-2);
  }
  .intro {
    margin: 0 0 var(--space-4);
    font-size: var(--text-sm);
  }
  .overview-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: var(--space-4);
    margin-bottom: var(--space-6);
  }
  .sla-card {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-xl);
    padding: var(--space-4);
    text-align: left;
    cursor: pointer;
    box-shadow: var(--shadow-sm);
    color: var(--color-text);
  }
  .sla-card:hover,
  .sla-card.selected {
    border-color: var(--color-primary);
  }
  .sla-card.selected {
    box-shadow: 0 0 0 1px var(--color-primary), var(--shadow-md);
  }
  .sla-card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: var(--space-2);
  }
  .sla-name {
    font-weight: 600;
    color: var(--color-text-heading);
  }
  .sla-window {
    font-size: var(--text-sm);
    color: var(--color-text-muted);
  }
  .sla-pct {
    font-size: var(--text-xl);
    font-weight: 700;
    font-family: var(--mono);
    margin-bottom: var(--space-1);
  }
  .sla-meta {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2) var(--space-4);
    font-size: var(--text-sm);
    color: var(--color-text-muted);
  }
  .detail-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: var(--space-3);
    margin-bottom: var(--space-4);
  }
  .detail-header h3 {
    margin: 0;
  }
  .detail-actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
  }
  .config-info {
    display: flex;
    gap: var(--space-6);
    padding: var(--space-3) var(--space-4);
    margin: var(--space-4) 0;
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-lg);
    font-size: var(--text-base);
    color: var(--color-text-muted);
  }
  .field-error {
    color: var(--color-red);
    font-size: var(--text-sm);
  }
</style>
