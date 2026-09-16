<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api, type RecentCapture } from '../../lib/api';
  import { formatBytes } from '../../lib/format';
  import { showToast } from '../../lib/toast';

  /** How often the ring is re-read while the page is open. */
  const POLL_MS = 5_000;

  let captures: RecentCapture[] = $state([]);
  let capacity = $state(50);
  let loading = $state(true);
  let error = $state('');
  /** The 503 case: a `--workers` node, whose ring lives in the workers. */
  let unavailable = $state('');
  let expanded: string | null = $state(null);
  let timer: ReturnType<typeof setInterval> | undefined;

  async function load() {
    const res = await api.listRecentCaptures();
    loading = false;
    if (res.error) {
      if (res.error.code === 'service_unavailable') {
        unavailable = res.error.message;
        error = '';
      } else {
        error = res.error.message;
      }
      return;
    }
    unavailable = '';
    error = '';
    captures = res.data?.captures ?? [];
    capacity = res.data?.capacity ?? capacity;
  }

  onMount(() => {
    void load();
    timer = setInterval(() => void load(), POLL_MS);
  });

  onDestroy(() => {
    if (timer) clearInterval(timer);
  });

  async function download(c: RecentCapture) {
    const res = await api.downloadRecentCapture(c.request_id, c.rule_id);
    if (!res.ok) showToast(res.message, 'error');
  }

  function rowKey(c: RecentCapture): string {
    return `${c.request_id}:${c.rule_id}`;
  }

  function bodySummary(half: RecentCapture['request'] | RecentCapture['response']): string {
    if (half.body_skipped) return `skipped (${half.body_skipped})`;
    const parts = [formatBytes(half.body_bytes_total)];
    if (half.truncated) parts.push('truncated');
    if (half.body_encoding) parts.push(half.body_encoding);
    return parts.join(', ');
  }
</script>

<section class="recent">
  <div class="page-header">
    <h2>Recent captures</h2>
    <span class="text-muted small">last {capacity} on this process, bodies cut at 4 KiB in the list</span>
  </div>

  {#if unavailable}
    <div class="ring-unavailable" role="note">
      <strong>The ring is not available on this node.</strong>
      <p>{unavailable}</p>
    </div>
  {:else if error}
    <div class="error-banner">{error}</div>
  {:else if loading}
    <p class="loading">Loading recent captures...</p>
  {:else if captures.length === 0}
    <div class="empty-state">
      <p>No capture has been emitted by this process yet.</p>
      <p class="text-muted small">Records appear here as rules admit exchanges; the sinks receive the same records.</p>
    </div>
  {:else}
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Rule</th>
            <th>Request</th>
            <th>Status</th>
            <th>Client</th>
            <th>Latency</th>
            <th>Bodies</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each captures as c (rowKey(c))}
            <tr>
              <td class="mono small">{new Date(c.timestamp).toLocaleString()}</td>
              <td>{c.rule_name}</td>
              <td class="mono small">{c.request.method} {c.request.uri}</td>
              <td>
                <span class="badge {c.response.status >= 500 ? 'badge-red' : c.response.status >= 400 ? 'badge-orange' : 'badge-green'}">
                  {c.response.status}
                </span>
                {#if c.error}<span class="text-muted small"> {c.error}</span>{/if}
              </td>
              <td class="mono small">{c.client_ip}</td>
              <td>{c.latency_ms} ms</td>
              <td class="small">req {bodySummary(c.request)}; resp {bodySummary(c.response)}</td>
              <td class="actions">
                <button class="btn btn-secondary btn-sm" onclick={() => (expanded = expanded === rowKey(c) ? null : rowKey(c))}>
                  {expanded === rowKey(c) ? 'Hide' : 'Show'}
                </button>
                <button
                  class="btn btn-secondary btn-sm"
                  onclick={() => download(c)}
                  aria-label="Download capture {c.request_id}"
                  data-request-id={c.request_id}
                >
                  Download
                </button>
              </td>
            </tr>
            {#if expanded === rowKey(c)}
              <tr class="detail-row">
                <td colspan="8">
                  <div class="detail">
                    <div>
                      <h4>Request <span class="mono small">{c.request.version}</span></h4>
                      <ul class="headers mono small">
                        {#each c.request.headers as [name, value], i (i)}
                          <li><span class="hname">{name}</span>: {value}</li>
                        {/each}
                      </ul>
                      {#if c.request.body !== null}
                        <pre class="body">{c.request.body}</pre>
                        {#if c.request.body_elided}
                          <p class="hint">Cut at 4 KiB of {c.request.body_elided_total} in the list; download for the whole body.</p>
                        {/if}
                      {/if}
                    </div>
                    <div>
                      <h4>Response <span class="mono small">{c.backend}</span></h4>
                      <ul class="headers mono small">
                        {#each c.response.headers as [name, value], i (i)}
                          <li><span class="hname">{name}</span>: {value}</li>
                        {/each}
                      </ul>
                      {#if c.response.body !== null}
                        <pre class="body">{c.response.body}</pre>
                        {#if c.response.body_elided}
                          <p class="hint">Cut at 4 KiB of {c.response.body_elided_total} in the list; download for the whole body.</p>
                        {/if}
                      {/if}
                      <p class="hint">The response body is the upstream's, before any rewrite this proxy applied.</p>
                    </div>
                  </div>
                  <p class="mono small text-muted">request_id {c.request_id}</p>
                </td>
              </tr>
            {/if}
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<style>
  .recent { margin-top: var(--space-6); }
  .recent h2 { font-size: 1.125rem; margin: 0; }
  .ring-unavailable { border: 1px solid var(--color-orange); border-radius: var(--radius-md); padding: var(--space-3) var(--space-4); background: var(--color-bg-card); }
  .ring-unavailable p { margin: var(--space-2) 0 0; color: var(--color-text-muted); }
  .btn-sm { padding: 0.25rem 0.5rem; font-size: var(--text-sm); }
  .detail-row td { background: var(--color-bg-hover); }
  .detail { display: grid; grid-template-columns: 1fr 1fr; gap: var(--space-4); }
  .detail h4 { margin: 0 0 var(--space-2); }
  .headers { list-style: none; padding: 0; margin: 0 0 var(--space-2); }
  .hname { color: var(--color-text-muted); }
  .body { max-height: 240px; overflow: auto; white-space: pre-wrap; word-break: break-all; font-size: var(--text-xs); background: var(--color-bg-card); border: 1px solid var(--color-border); border-radius: var(--radius-md); padding: var(--space-2); }
  @media (max-width: 900px) { .detail { grid-template-columns: 1fr; } }
</style>
