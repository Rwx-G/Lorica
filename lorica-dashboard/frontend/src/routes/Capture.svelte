<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api, type CaptureRuleResponse, type RouteResponse } from '../lib/api';
  import { canWrite, isSuperAdmin } from '../lib/auth';
  import { describeEmit, formatTimeUntil, isExpired, remainingBudget } from '../lib/capture';
  import { showToast } from '../lib/toast';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import CaptureRuleForm from '../components/capture/CaptureRuleForm.svelte';
  import RecentCaptures from '../components/capture/RecentCaptures.svelte';

  /** The counters are flushed to the store every five seconds; poll at that cadence. */
  const POLL_MS = 5_000;

  let rules: CaptureRuleResponse[] = $state([]);
  let routes: RouteResponse[] = $state([]);
  let loading = $state(true);
  let error = $state('');
  let now = $state(new Date());
  let timer: ReturnType<typeof setInterval> | undefined;

  let showForm = $state(false);
  let editing: CaptureRuleResponse | null = $state(null);
  let deleting: CaptureRuleResponse | null = $state(null);

  async function loadData() {
    const [rulesRes, routesRes] = await Promise.all([api.listCaptureRules(), api.listRoutes()]);
    loading = false;
    now = new Date();
    if (rulesRes.error) {
      error = rulesRes.error.message;
      return;
    }
    error = '';
    rules = rulesRes.data?.rules ?? [];
    if (routesRes.data) routes = routesRes.data.routes;
  }

  onMount(() => {
    void loadData();
    timer = setInterval(() => void loadData(), POLL_MS);
  });

  onDestroy(() => {
    if (timer) clearInterval(timer);
  });

  function routeLabel(routeId: string): string {
    const r = routes.find((rt) => rt.id === routeId);
    return r ? `${r.hostname}${r.path_prefix}` : routeId;
  }

  function openCreate() {
    editing = null;
    showForm = true;
  }

  function openEdit(rule: CaptureRuleResponse) {
    editing = rule;
    showForm = true;
  }

  async function disable(rule: CaptureRuleResponse) {
    const res = await api.disableCaptureRule(rule.id);
    if (res.error) {
      showToast(res.error.message, 'error');
      return;
    }
    showToast(`Capture rule "${rule.name}" stopped`, 'success');
    await loadData();
  }

  async function handleDelete() {
    if (!deleting) return;
    const res = await api.deleteCaptureRule(deleting.id);
    if (res.error) showToast(res.error.message, 'error');
    else showToast('Capture rule deleted', 'success');
    deleting = null;
    await loadData();
  }

  function statusOf(rule: CaptureRuleResponse): { label: string; cls: string } {
    if (!rule.enabled) return { label: 'Disabled', cls: 'badge-orange' };
    if (isExpired(rule, now)) return { label: 'Expired', cls: 'badge-orange' };
    if (remainingBudget(rule) === 0) return { label: 'Budget spent', cls: 'badge-orange' };
    return { label: 'Recording', cls: 'badge-green' };
  }
</script>

<div class="capture-page">
  <div class="page-header">
    <h1>Capture</h1>
    {#if $isSuperAdmin}
      <button class="btn btn-primary" onclick={openCreate} disabled={routes.length === 0}>New rule</button>
    {/if}
  </div>
  <p class="hint">
    A capture rule keeps the full request and response for a subset of traffic on one route. The
    record joins the access log on <span class="mono">request_id</span>; credentials in headers and
    named query parameters are redacted, bodies are not. See docs/capture.md.
  </p>

  {#if error}
    <div class="error-banner">{error}</div>
  {/if}

  {#if loading}
    <p class="loading">Loading capture rules...</p>
  {:else if rules.length === 0}
    <div class="empty-state">
      <p>No capture rule on this node.</p>
      {#if $isSuperAdmin && routes.length > 0}
        <button class="btn btn-primary" onclick={openCreate}>Arm your first rule</button>
      {:else if $isSuperAdmin}
        <p class="text-muted small">Create a route first: a rule records exactly one.</p>
      {/if}
    </div>
  {:else}
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Route</th>
            <th>Emits on</th>
            <th>Emitted</th>
            <th>Dropped</th>
            <th>Remaining</th>
            <th>Expires</th>
            <th>Status</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each rules as rule (rule.id)}
            {@const status = statusOf(rule)}
            <tr>
              <td class="rule-name">{rule.name}</td>
              <td>{routeLabel(rule.route_id)}</td>
              <td class="small">{describeEmit(rule.emit)}</td>
              <td>{rule.captures_emitted}</td>
              <td>{rule.captures_dropped}</td>
              <td>{remainingBudget(rule)} / {rule.limits.max_captures}</td>
              <td title={new Date(rule.expires_at).toLocaleString()}>{formatTimeUntil(new Date(rule.expires_at), now)}</td>
              <td><span class="badge {status.cls}">{status.label}</span></td>
              <td class="actions">
                {#if $canWrite && rule.enabled}
                  <button class="btn btn-secondary btn-sm" onclick={() => disable(rule)} aria-label="Disable {rule.name}">
                    Disable
                  </button>
                {/if}
                {#if $isSuperAdmin}
                  <button class="btn btn-secondary btn-sm" onclick={() => openEdit(rule)} aria-label="Edit {rule.name}">
                    Edit
                  </button>
                  <button class="btn btn-danger btn-sm" onclick={() => (deleting = rule)} aria-label="Delete {rule.name}">
                    Delete
                  </button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <p class="hint">
      Counters are per process and flushed every few seconds. Under --workers each worker counts its
      own; the expiry is the one bound every node agrees on. A rule that spends its total disables
      itself and stays listed.
    </p>
  {/if}

  <RecentCaptures />

  {#if deleting}
    <ConfirmDialog
      title="Delete capture rule"
      message="Delete capture rule {deleting.name}? Records already written are not touched."
      confirmLabel="Delete"
      onconfirm={handleDelete}
      oncancel={() => (deleting = null)}
    />
  {/if}

  {#if showForm}
    <CaptureRuleForm
      {routes}
      {editing}
      onsaved={() => { showForm = false; void loadData(); }}
      oncancel={() => (showForm = false)}
    />
  {/if}
</div>

<style>
  .capture-page { max-width: none; }
  .rule-name { font-weight: 600; color: var(--color-text-heading); }
  .btn-sm { padding: 0.25rem 0.5rem; font-size: var(--text-sm); }
</style>
