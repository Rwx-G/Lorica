<script lang="ts">
  import { onMount, onDestroy } from 'svelte';

  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import { api } from '../lib/api';
  import type { CertificateResponse, MintedTokenResponse } from '../lib/api';
  import { isSuperAdmin, isSuperAdminRole } from '../lib/auth';
  import {
    clusterStatus,
    breakGlassActive,
    gaugePercent,
    joinCommand,
    secondsUntil,
    type ClusterNodeResponse,
    type FleetBanRow,
    type FleetWafRow,
  } from '../lib/cluster';
  import { showToast } from '../lib/toast';

  /** How often the roster refreshes while the page is open. */
  const REFRESH_MS = 10_000;

  let nodes = $state<ClusterNodeResponse[]>([]);
  let loading = $state(true);
  let loadError = $state<string | null>(null);
  let timer: ReturnType<typeof setInterval> | null = null;

  let selected = $state<ClusterNodeResponse | null>(null);
  let revoking = $state<ClusterNodeResponse | null>(null);

  // Drawer contents (AC #3), loaded per node rather than with the
  // roster: the roster refreshes every ten seconds for every node, and
  // these three reads are only worth making for the one node an
  // operator has open.
  const DRAWER_EVENTS = 10;
  let drawerWaf = $state<FleetWafRow[]>([]);
  let drawerBans = $state<FleetBanRow[]>([]);
  let drawerError = $state<string | null>(null);
  /**
   * The fleet's certificates, fetched once per page mount rather than
   * per drawer: the set is fleet-wide and identical whichever node is
   * open, so refetching it on every node switch is work nobody asked
   * for.
   */
  let certificates = $state<CertificateResponse[]>([]);
  /** The node id `loadDrawer` last ran for, so a roster poll that
      replaces the `selected` object does not refetch everything. */
  let drawerLoadedFor: string | null = null;

  async function loadDrawer(nodeId: string) {
    const [waf, bans] = await Promise.all([
      api.getFleetWafEvents({ node: nodeId, limit: DRAWER_EVENTS }),
      api.getFleetBans(nodeId),
    ]);
    // Two nodes opened in quick succession race here. Without this
    // guard the slower response wins and the drawer shows one node's
    // WAF events under another node's name, which in the incident this
    // drawer exists for is worse than showing nothing.
    if (drawerLoadedFor !== nodeId) return;
    // A failed read must not read as "this node reported nothing".
    // That is the sentence an operator would act on.
    drawerError = waf.error?.message ?? bans.error?.message ?? null;
    drawerWaf = waf.data?.rows ?? [];
    drawerBans = bans.data ?? [];
  }

  async function loadCertificates() {
    const res = await api.listCertificates();
    if (res.data) certificates = res.data.certificates;
  }

  $effect(() => {
    const id = selected?.node.node_id ?? null;
    if (id === null) {
      drawerLoadedFor = null;
      return;
    }
    if (id === drawerLoadedFor) return;
    drawerLoadedFor = id;
    drawerWaf = [];
    drawerBans = [];
    drawerError = null;
    void loadDrawer(id);
  });

  /**
   * The certificates whose private keys this node receives.
   *
   * Reported by the control plane, not derived here. The first version
   * of this intersected `selected_for_hostnames` with each
   * certificate's subject names and claimed to reproduce the push
   * path's rule. It did not: that field deliberately omits fleet-wide
   * routes, which entitle every Active node, so a node holding every
   * fleet-wide certificate was shown as holding none, on the page
   * built to answer exactly that question.
   */
  function certificatesFor(node: ClusterNodeResponse): CertificateResponse[] {
    const entitled = new Set(node.certificate_ids);
    return certificates.filter((c) => entitled.has(c.id));
  }

  function daysUntil(iso: string): number {
    return Math.floor((Date.parse(iso) - Date.now()) / 86_400_000);
  }

  /** Bytes as the nearest sensible unit, for a gauge caption. */
  function bytes(n: number): string {
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let value = n;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit += 1;
    }
    return `${value < 10 && unit > 0 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
  }

  // Token dialog.
  let showMint = $state(false);
  let mintName = $state('');
  let mintTtl = $state(3600);
  let mintCidr = $state('');
  let minting = $state(false);
  let minted = $state<MintedTokenResponse | null>(null);

  const status = $derived($clusterStatus);
  const superAdmin = $derived($isSuperAdmin);
  /**
   * Role alone, ignoring read-only mode. Break-glass and leave are the
   * two ways out of read-only mode, so gating them on it would lock
   * the door from the inside: an operator on an edge whose control
   * plane is unreachable would have no way to act on that node.
   */
  const superAdminRole = $derived($isSuperAdminRole);

  // Break-glass and leave (Story 9.4 AC #11, 9.3 AC #13). Follower
  // only; the control plane owns the configuration and has nothing to
  // break out of.
  let glassDuration = $state(900);
  let glassBusy = $state(false);
  let leaving = $state(false);
  let confirmLeave = $state(false);

  async function openGlass() {
    glassBusy = true;
    const res = await api.openBreakGlass(glassDuration);
    glassBusy = false;
    if (res.error) {
      showToast(res.error.message, 'error');
      return;
    }
    showToast('Break-glass open; local edits are allowed until it closes');
    await load();
  }

  async function closeGlass() {
    glassBusy = true;
    const res = await api.closeBreakGlass();
    glassBusy = false;
    if (res.error) {
      showToast(res.error.message, 'error');
      return;
    }
    showToast('Break-glass closed; this node will reconcile with the control plane');
    await load();
  }

  async function leaveFleet() {
    confirmLeave = false;
    leaving = true;
    const res = await api.leaveCluster();
    leaving = false;
    if (res.error) {
      showToast(res.error.message, 'error');
      return;
    }
    // A node that left is no longer a follower, so the whole cluster
    // surface should disappear. Reload rather than patch the store:
    // every derived predicate on the page depends on the role.
    showToast(
      res.data?.control_plane_notified === false
        ? 'Left the fleet, but the control plane could not be told: revoke this node there'
        : 'Left the fleet',
    );
    await load();
  }

  async function load() {
    // The status is polled once, by `Dashboard.svelte`, which owns the
    // store; this page reads it. Two writers on one store meant two
    // requests per cycle and a window where the slower of two
    // overlapping responses landed last, briefly re-enabling or
    // hiding the mutation controls that derive from it.
    const nodesRes = await api.listClusterNodes();
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
    void loadCertificates();
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

    <section class="drawer-section">
      <h3>Resources</h3>
      {#if !node.resources}
        <p class="muted">
          {node.connected
            ? 'This node has not reported a reading yet.'
            : 'Not connected: readings are session state and are re-learned on reconnect.'}
        </p>
      {:else}
        {@const res = node.resources}
        {@const mem = gaugePercent(res.memory_used_bytes, res.memory_total_bytes)}
        {@const disk = gaugePercent(res.disk_used_bytes, res.disk_total_bytes)}
        <div class="gauge">
          <span class="gauge-label">CPU</span>
          <div class="gauge-track">
            <!--
              Bounded here as well as at the wire decode boundary. The
              other two gauges go through `gaugePercent`, which caps;
              leaving this one to depend on a `.min(100)` in another
              crate means a regression there widens an element on the
              operator's page.
            -->
            <div class="gauge-fill" style="width: {gaugePercent(res.cpu_percent, 100) ?? 0}%"></div>
          </div>
          <span class="gauge-value">{res.cpu_percent}%</span>
        </div>
        <div class="gauge">
          <span class="gauge-label">Memory</span>
          <div class="gauge-track">
            <div class="gauge-fill" style="width: {mem ?? 0}%"></div>
          </div>
          <span class="gauge-value">
            {#if mem === null}
              unknown
            {:else}
              {mem}% of {bytes(res.memory_total_bytes)}
            {/if}
          </span>
        </div>
        <div class="gauge">
          <span class="gauge-label">Disk</span>
          <div class="gauge-track">
            <div class="gauge-fill" style="width: {disk ?? 0}%"></div>
          </div>
          <span class="gauge-value">
            {#if disk === null}
              unknown
            {:else}
              {disk}% of {bytes(res.disk_total_bytes)}
            {/if}
          </span>
        </div>
        <p class="muted">
          The data directory's filesystem, not the root one: what fills up on
          a proxy is where its logs and databases live.
        </p>
      {/if}
    </section>

    <section class="drawer-section">
      <h3>Certificates</h3>
      {#if certificatesFor(node).length === 0}
        <p class="muted">
          No route selector names this node, so it receives no certificate
          keys.
        </p>
      {:else}
        <table class="mini-table">
          <thead>
            <tr><th>Subject</th><th>Expires</th></tr>
          </thead>
          <tbody>
            {#each certificatesFor(node) as cert (cert.id)}
              {@const days = daysUntil(cert.not_after)}
              <tr>
                <td class="mono">{cert.domain}</td>
                <td class:expiry-warn={days < 30} class:expiry-crit={days < 7}>
                  {#if days < 0}
                    expired
                  {:else}
                    {days}d
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>

    {#if drawerError}
      <p class="error-text">
        Could not read this node's recent activity: {drawerError}
      </p>
    {/if}

    <section class="drawer-section">
      <h3>Recent WAF events</h3>
      {#if drawerWaf.length === 0}
        <p class="muted">Nothing this node reported.</p>
      {:else}
        <table class="mini-table">
          <thead>
            <tr><th>Time</th><th>Client</th><th>Rule</th><th>Action</th></tr>
          </thead>
          <tbody>
            {#each drawerWaf as event (event.id)}
              <tr>
                <td class="mono">{event.timestamp}</td>
                <td class="mono">{event.client_ip}</td>
                <td class="mono">{event.rule_id}</td>
                <td>{event.action}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>

    <section class="drawer-section">
      <h3>Bans this node holds</h3>
      {#if drawerBans.length === 0}
        <p class="muted">None reported.</p>
      {:else}
        <table class="mini-table">
          <thead>
            <tr><th>Client</th><th>Reason</th><th>Expires in</th></tr>
          </thead>
          <tbody>
            {#each drawerBans as ban (ban.client_ip)}
              <tr>
                <td class="mono">{ban.client_ip}</td>
                <td>{ban.reason}</td>
                <td>{ban.remaining_s}s</td>
              </tr>
            {/each}
          </tbody>
        </table>
        <p class="muted">
          A snapshot of what this node last reported. Bans live in its memory,
          so a restart clears them, and lifting one is done on that node.
        </p>
      {/if}
    </section>

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

{#if status?.role === 'follower' && superAdminRole}
  <!--
    Gated on the role alone, never on read-only mode. These are the two
    ways out of read-only mode, so gating them on it would lock the door
    from the inside: an operator on an edge whose control plane is
    unreachable would see a banner explaining that edits are refused and
    no way to act.
  -->
  <section class="follower-actions">
    <h2>This node</h2>
    {#if breakGlassActive(status)}
      <p class="muted">
        A break-glass window is open. Closing it now makes this node pull the
        control plane's current configuration and discard local edits.
      </p>
      <button class="btn-secondary" disabled={glassBusy} onclick={() => void closeGlass()}>
        Close break-glass
      </button>
    {:else}
      <p class="muted">
        Configuration is owned by {status.control_plane}. Break-glass allows
        local edits for a bounded window, for use when the control plane
        cannot be reached. Edits are reconciled away when it closes, and the
        window is audited here and reported in every heartbeat.
      </p>
      <label for="glass-duration">Window (seconds)</label>
      <input
        id="glass-duration"
        type="number"
        bind:value={glassDuration}
        min="1"
        max="86400"
      />
      <button class="btn-secondary" disabled={glassBusy} onclick={() => void openGlass()}>
        Open break-glass
      </button>
    {/if}

    <p class="muted">
      Leaving tells the control plane over the live session, then wipes this
      node's fleet identity. If the control plane cannot be reached the node
      still leaves and must be revoked there by hand.
    </p>
    <button class="btn-danger" disabled={leaving} onclick={() => (confirmLeave = true)}>
      Leave the fleet
    </button>
  </section>
{/if}

{#if confirmLeave}
  <ConfirmDialog
    title="Leave the fleet?"
    message="This node stops receiving configuration and certificate keys from the control plane and keeps only what it already has. Its fleet identity is wiped, so rejoining needs a new join token."
    confirmLabel="Leave"
    onconfirm={() => void leaveFleet()}
    oncancel={() => (confirmLeave = false)}
  />
{/if}

<style>
  .drawer-section {
    border-top: 1px solid var(--color-border);
    padding-top: 0.75rem;
    margin-top: 0.75rem;
  }
  .drawer-section h3 {
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--color-text-muted);
    margin: 0 0 0.5rem;
  }
  .mini-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.8rem;
  }
  .mini-table th {
    text-align: left;
    font-weight: 500;
    color: var(--color-text-muted);
    padding-bottom: 0.25rem;
  }
  .mini-table td {
    padding: 0.2rem 0.4rem 0.2rem 0;
    border-top: 1px solid var(--color-border);
  }
  .expiry-warn {
    color: var(--color-orange);
  }
  .expiry-crit {
    color: var(--color-red);
    font-weight: 600;
  }
  .gauge {
    display: grid;
    grid-template-columns: 4.5rem 1fr auto;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8rem;
    margin-bottom: 0.35rem;
  }
  .gauge-label {
    color: var(--color-text-muted);
  }
  .gauge-track {
    height: 0.5rem;
    border-radius: 0.25rem;
    background: var(--color-border);
    overflow: hidden;
  }
  .gauge-fill {
    height: 100%;
    background: var(--color-orange);
  }
  .gauge-value {
    font-variant-numeric: tabular-nums;
  }
  .follower-actions {
    margin: 1rem 0;
    padding: 1rem;
    border: 1px solid var(--color-border);
    border-radius: 0.5rem;
    max-width: 40rem;
  }
  .follower-actions h2 {
    font-size: 0.95rem;
    margin: 0 0 0.5rem;
  }
  .follower-actions input {
    display: block;
    margin-bottom: 0.5rem;
  }
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
