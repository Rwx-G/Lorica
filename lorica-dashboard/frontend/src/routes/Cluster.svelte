<script lang="ts">
  import { onMount, onDestroy } from 'svelte';

  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import { api } from '../lib/api';
  import type { MintedTokenResponse } from '../lib/api';
  import { isSuperAdmin } from '../lib/auth';
  import {
    clusterStatus,
    breakGlassActive,
    joinCommand,
    secondsUntil,
    type ClusterNodeResponse,
    type ClusterStatus,
  } from '../lib/cluster';
  import { showToast } from '../lib/toast';

  /** How often the roster refreshes while the page is open. */
  const REFRESH_MS = 10_000;

  let nodes = $state<ClusterNodeResponse[]>([]);
  let status = $state<ClusterStatus | null>(null);
  let loading = $state(true);
  let loadError = $state<string | null>(null);
  let timer: ReturnType<typeof setInterval> | null = null;

  let selected = $state<ClusterNodeResponse | null>(null);
  let revoking = $state<ClusterNodeResponse | null>(null);

  // Token dialog.
  let showMint = $state(false);
  let mintName = $state('');
  let mintTtl = $state(3600);
  let mintCidr = $state('');
  let minting = $state(false);
  let minted = $state<MintedTokenResponse | null>(null);

  const superAdmin = $derived($isSuperAdmin);

  async function load() {
    const [statusRes, nodesRes] = await Promise.all([
      api.getClusterStatus(),
      api.listClusterNodes(),
    ]);
    if (statusRes.data) {
      status = statusRes.data;
      clusterStatus.set(statusRes.data);
    }
    if (nodesRes.error) {
      loadError = nodesRes.error.message;
    } else {
      loadError = null;
      nodes = nodesRes.data ?? [];
      // Keep the open drawer pointing at fresh data rather than a
      // snapshot from whenever it was opened.
      if (selected) {
        selected = nodes.find((n) => n.node.node_id === selected?.node.node_id) ?? null;
      }
    }
    loading = false;
  }

  onMount(() => {
    void load();
    timer = setInterval(() => void load(), REFRESH_MS);
  });

  onDestroy(() => {
    if (timer !== null) clearInterval(timer);
  });

  async function activate(node: ClusterNodeResponse) {
    const res = await api.activateClusterNode(node.node.node_id);
    if (res.error) {
      showToast(res.error.message, 'error');
      return;
    }
    showToast(`${node.node.name} activated`);
    await load();
  }

  async function confirmRevoke() {
    const node = revoking;
    revoking = null;
    if (!node) return;
    const res = await api.revokeClusterNode(node.node.node_id);
    if (res.error) {
      showToast(res.error.message, 'error');
      return;
    }
    showToast(`${node.node.name} revoked`);
    if (selected?.node.node_id === node.node.node_id) selected = null;
    await load();
  }

  async function mint() {
    minting = true;
    const res = await api.mintClusterToken({
      node_name: mintName.trim(),
      ttl_seconds: mintTtl,
      ...(mintCidr.trim() ? { source_cidr: mintCidr.trim() } : {}),
    });
    minting = false;
    if (res.error) {
      showToast(res.error.message, 'error');
      return;
    }
    minted = res.data ?? null;
  }

  function closeMint() {
    showMint = false;
    minted = null;
    mintName = '';
    mintCidr = '';
  }

  async function copy(text: string, what: string) {
    try {
      await navigator.clipboard.writeText(text);
      showToast(`${what} copied`);
    } catch {
      showToast('Could not copy; select the text manually', 'error');
    }
  }

  function driftedFrom(node: ClusterNodeResponse): boolean {
    if (!status || node.node.status !== 'active') return false;
    return node.node.applied_config_generation !== status.applied_config_generation;
  }

  function relative(iso: string | null): string {
    if (!iso) return 'never';
    const t = Date.parse(iso);
    if (!Number.isFinite(t)) return 'unknown';
    const secs = Math.max(0, Math.floor((Date.now() - t) / 1000));
    if (secs < 60) return `${secs}s ago`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    return `${Math.floor(secs / 3600)}h ago`;
  }

  const controlPlaneAddress = $derived(status?.control_plane ?? 'cp.example.com:9444');
</script>

<div class="page">
  <header class="page-header">
    <div>
      <h1>Cluster</h1>
      <p class="subtitle">
        {#if status?.role === 'control_plane'}
          This node is the control plane. It owns the fleet's configuration and
          certificate authority.
        {:else if status?.role === 'follower'}
          This node is a follower of {status.control_plane}. Its configuration is
          replaced from the control plane on every apply.
        {:else}
          This node is not part of a fleet.
        {/if}
      </p>
    </div>
    {#if status?.role === 'control_plane' && superAdmin}
      <button class="btn-primary" onclick={() => (showMint = true)}>Add node</button>
    {/if}
  </header>

  {#if loading}
    <p class="muted">Loading the fleet…</p>
  {:else if loadError}
    <p class="error-text">{loadError}</p>
  {:else if status?.role !== 'control_plane'}
    <p class="muted">
      The node roster is held by the control plane. Open this page there to see
      the fleet.
    </p>
  {:else if nodes.length === 0}
    <p class="muted">
      No node has enrolled yet. Use <strong>Add node</strong> to mint a join
      token, then run <code>lorica cluster join</code> on the new machine.
    </p>
  {:else}
    <table class="data-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Status</th>
          <th>Connected</th>
          <th>Version</th>
          <th>Schema</th>
          <th>Applied</th>
          <th>Last seen</th>
        </tr>
      </thead>
      <tbody>
        {#each nodes as n (n.node.node_id)}
          <tr class="row" onclick={() => (selected = n)}>
            <td>
              <button class="link-btn" onclick={(e) => { e.stopPropagation(); selected = n; }}>
                {n.node.name}
              </button>
            </td>
            <td><span class="pill pill-{n.node.status}">{n.node.status}</span></td>
            <td>
              {#if n.connected}
                <span class="pill pill-ok">connected</span>
              {:else}
                <span class="pill pill-off">offline</span>
              {/if}
            </td>
            <td>{n.node.version || '-'}</td>
            <td>{n.node.schema_version}</td>
            <td>
              {n.node.applied_config_generation}
              {#if driftedFrom(n)}
                <span class="pill pill-warn" title="Behind the control plane's generation">
                  drift
                </span>
              {/if}
            </td>
            <td>{relative(n.node.last_seen_at)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

{#if selected}
  {@const node = selected}
  <aside class="drawer" aria-label="Node detail">
    <header class="drawer-header">
      <h2>{node.node.name}</h2>
      <button class="icon-btn" aria-label="Close" onclick={() => (selected = null)}>x</button>
    </header>

    <dl class="detail">
      <dt>Node id</dt>
      <dd class="mono">{node.node.node_id}</dd>
      <dt>Status</dt>
      <dd><span class="pill pill-{node.node.status}">{node.node.status}</span></dd>
      <dt>Session</dt>
      <dd>{node.connected ? (node.session_peer ?? 'connected') : 'not connected'}</dd>
      <dt>Version</dt>
      <dd>{node.node.version || '-'} (schema {node.node.schema_version})</dd>
      <dt>Applied generation</dt>
      <dd>{node.node.applied_config_generation}</dd>
      <dt>Applied hash</dt>
      <dd class="mono">{node.node.applied_config_hash || '-'}</dd>
      <dt>Enrolled</dt>
      <dd>{node.node.enrolled_at}</dd>
      <dt>Last seen</dt>
      <dd>{relative(node.node.last_seen_at)}</dd>
    </dl>

    {#if node.node.status === 'pending'}
      <section class="approve">
        <h3>Approve this node</h3>
        {#if node.selected_for_hostnames.length > 0}
          <p class="warn-text">
            Route selectors already name <strong>{node.node.name}</strong>. Activating
            it will start sending it the private keys for these hostnames:
          </p>
          <ul class="hostnames">
            {#each node.selected_for_hostnames as host (host)}
              <li class="mono">{host}</li>
            {/each}
          </ul>
        {:else}
          <p class="muted">
            No route selector names this node yet, so activating it sends no
            certificate keys until one does.
          </p>
        {/if}
        {#if superAdmin}
          <button class="btn-primary" onclick={() => void activate(node)}>
            Activate {node.node.name}
          </button>
        {/if}
      </section>
    {/if}

    {#if superAdmin && node.node.status !== 'revoked'}
      <footer class="drawer-footer">
        <button class="btn-danger" onclick={() => (revoking = node)}>Revoke node</button>
      </footer>
    {/if}
  </aside>
{/if}

{#if revoking}
  <ConfirmDialog
    title="Revoke {revoking.node.name}?"
    message="Its certificate goes on the revocation list and its session is dropped immediately. The node keeps serving the configuration it already has until it is stopped, and it cannot rejoin without a new token."
    confirmLabel="Revoke"
    onconfirm={() => void confirmRevoke()}
    oncancel={() => (revoking = null)}
  />
{/if}

{#if showMint}
  <div class="overlay" role="dialog" aria-modal="true">
    <div class="dialog wide">
      {#if !minted}
        <h2>Add a node</h2>
        <p class="muted">
          The token names the node it may enrol. That name is what route
          selectors resolve against, so it decides which certificate keys the
          node receives; binding it here is what makes the choice yours rather
          than the joining machine's.
        </p>
        <label for="mint-name">Node name</label>
        <input
          id="mint-name"
          bind:value={mintName}
          placeholder="edge-01"
          autocomplete="off"
        />
        <label for="mint-ttl">Valid for (seconds)</label>
        <input id="mint-ttl" type="number" bind:value={mintTtl} min="60" max="86400" />
        <label for="mint-cidr">Source CIDR (optional)</label>
        <input id="mint-cidr" bind:value={mintCidr} placeholder="192.0.2.0/24" autocomplete="off" />
        <div class="dialog-actions">
          <button class="btn-secondary" onclick={closeMint}>Cancel</button>
          <button
            class="btn-primary"
            disabled={minting || mintName.trim() === ''}
            onclick={() => void mint()}
          >
            {minting ? 'Minting…' : 'Mint token'}
          </button>
        </div>
      {:else}
        <!--
          Bound once here rather than read through `minted` at each use:
          the copy handler is a closure, and TypeScript cannot carry the
          `{#if !minted}` narrowing into a callback that runs later.
        -->
        {@const token = minted}
        <h2>Token for {token.bound_node_name}</h2>
        <p class="warn-text">
          This is shown once and is not recoverable. It expires in
          {secondsUntil(token.expires_at)} seconds.
        </p>

        <label for="join-cmd">1. Run this on the new node</label>
        <div class="copy-row">
          <code id="join-cmd" class="mono block">{joinCommand(controlPlaneAddress)}</code>
          <button
            class="btn-secondary"
            onclick={() => void copy(joinCommand(controlPlaneAddress), 'Command')}
          >
            Copy
          </button>
        </div>

        <label for="join-token">2. Paste the token into its stdin</label>
        <div class="copy-row">
          <code id="join-token" class="mono block secret">{token.token}</code>
          <button class="btn-secondary" onclick={() => void copy(token.token, 'Token')}>
            Copy
          </button>
        </div>
        <p class="muted">
          The token is deliberately kept off the command line: argv is readable
          through <code>/proc</code>, lands in shell history, and is logged
          verbatim by CI and configuration-management tools.
        </p>

        <div class="dialog-actions">
          <button class="btn-primary" onclick={closeMint}>Done</button>
        </div>
      {/if}
    </div>
  </div>
{/if}

{#if status && breakGlassActive(status)}
  <div class="glass-banner" role="status">
    Break-glass is open. Local edits are allowed on this node and will be
    overwritten when the window closes.
  </div>
{/if}

<style>
  .page {
    padding: 1.5rem;
  }
  .page-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 1rem;
    margin-bottom: 1.25rem;
  }
  h1 {
    margin: 0 0 0.25rem;
    font-size: 1.5rem;
  }
  .subtitle,
  .muted {
    color: var(--text-muted, #6b7280);
    margin: 0;
  }
  .error-text {
    color: var(--danger, #dc2626);
  }
  .warn-text {
    color: var(--warning, #b45309);
  }
  .data-table {
    width: 100%;
    border-collapse: collapse;
  }
  .data-table th,
  .data-table td {
    text-align: left;
    padding: 0.55rem 0.65rem;
    border-bottom: 1px solid var(--border, #e5e7eb);
  }
  .row {
    cursor: pointer;
  }
  .row:hover {
    background: var(--surface-hover, #f9fafb);
  }
  .link-btn {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent, #2563eb);
    cursor: pointer;
    font: inherit;
  }
  .pill {
    display: inline-block;
    padding: 0.1rem 0.45rem;
    border-radius: 999px;
    font-size: 0.75rem;
    border: 1px solid var(--border, #e5e7eb);
  }
  .pill-active,
  .pill-ok {
    background: #dcfce7;
    color: #166534;
  }
  .pill-pending,
  .pill-warn {
    background: #fef3c7;
    color: #92400e;
  }
  .pill-revoked,
  .pill-off {
    background: #f3f4f6;
    color: #4b5563;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.85rem;
  }
  .block {
    display: block;
    padding: 0.5rem;
    background: var(--surface-alt, #f3f4f6);
    border-radius: 4px;
    overflow-wrap: anywhere;
  }
  .secret {
    border: 1px dashed var(--warning, #b45309);
  }
  .drawer {
    position: fixed;
    top: 0;
    right: 0;
    width: min(30rem, 100%);
    height: 100%;
    background: var(--surface, #fff);
    border-left: 1px solid var(--border, #e5e7eb);
    padding: 1.25rem;
    overflow-y: auto;
    box-shadow: -4px 0 16px rgb(0 0 0 / 8%);
  }
  .drawer-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .drawer-header h2 {
    margin: 0;
    font-size: 1.15rem;
  }
  .icon-btn {
    background: none;
    border: none;
    font-size: 1.1rem;
    cursor: pointer;
  }
  .detail {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.35rem 0.9rem;
    margin: 1rem 0;
  }
  .detail dt {
    color: var(--text-muted, #6b7280);
    font-size: 0.85rem;
  }
  .detail dd {
    margin: 0;
    overflow-wrap: anywhere;
  }
  .approve {
    border-top: 1px solid var(--border, #e5e7eb);
    padding-top: 1rem;
  }
  .approve h3 {
    margin: 0 0 0.5rem;
    font-size: 1rem;
  }
  .hostnames {
    margin: 0.5rem 0 1rem;
    padding-left: 1.1rem;
  }
  .drawer-footer {
    border-top: 1px solid var(--border, #e5e7eb);
    margin-top: 1.25rem;
    padding-top: 1rem;
  }
  .overlay {
    position: fixed;
    inset: 0;
    background: rgb(0 0 0 / 45%);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 50;
  }
  .dialog {
    background: var(--surface, #fff);
    border-radius: 8px;
    padding: 1.25rem;
    width: min(34rem, 92vw);
  }
  .dialog h2 {
    margin: 0 0 0.5rem;
    font-size: 1.15rem;
  }
  .dialog label {
    display: block;
    margin: 0.85rem 0 0.25rem;
    font-size: 0.85rem;
    color: var(--text-muted, #6b7280);
  }
  .dialog input {
    width: 100%;
    padding: 0.45rem 0.55rem;
    border: 1px solid var(--border, #e5e7eb);
    border-radius: 4px;
    font: inherit;
  }
  .copy-row {
    display: flex;
    gap: 0.5rem;
    align-items: flex-start;
  }
  .copy-row code {
    flex: 1;
  }
  .dialog-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    margin-top: 1.25rem;
  }
  .glass-banner {
    position: fixed;
    bottom: 0;
    left: 0;
    right: 0;
    padding: 0.6rem 1rem;
    background: var(--warning, #b45309);
    color: #fff;
    text-align: center;
  }
</style>
