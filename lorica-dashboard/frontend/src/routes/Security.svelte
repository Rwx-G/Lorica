<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type WafEvent, type WafCategoryCount, type WafRuleSummary, type BlocklistStatus, type CustomWafRule, type BanEntry } from '../lib/api';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import { showToast } from '../lib/toast';

  let events: WafEvent[] = $state([]);
  let stats: { total_events: number; rule_count: number; by_category: WafCategoryCount[] } = $state({
    total_events: 0,
    rule_count: 0,
    by_category: [],
  });
  let rules: WafRuleSummary[] = $state([]);
  let rulesEnabled = $state(0);
  let blocklist: BlocklistStatus = $state({ enabled: false, ip_count: 0, source: '' });
  let blocklistLoading = $state(false);
  let customRules: CustomWafRule[] = $state([]);
  let loading = $state(true);
  let error = $state('');
  let filterCategory = $state('');
  let activeTab: 'events' | 'rules' | 'blocklist' | 'custom' | 'bans' = $state('events');
  let showClearConfirm = $state(false);
  let bans: BanEntry[] = $state([]);
  let bansLoading = $state(false);
  let unbanningIp: string | null = $state(null);
  let bansRefreshTimer: ReturnType<typeof setInterval> | null = $state(null);

  // Custom rule form
  let showCustomForm = $state(false);
  let crId = $state(10000);
  let crDescription = $state('');
  let crCategory = $state('sql_injection');
  let crPattern = $state('');
  let crSeverity = $state(3);
  let crError = $state('');
  let crSubmitting = $state(false);
  let deletingCustomRule: CustomWafRule | null = $state(null);

  async function loadData() {
    loading = true;
    error = '';
    const [eventsRes, statsRes, rulesRes, blRes, crRes] = await Promise.all([
      api.getWafEvents({ limit: 100, category: filterCategory || undefined }),
      api.getWafStats(),
      api.getWafRules(),
      api.getBlocklistStatus(),
      api.listCustomRules(),
    ]);

    if (eventsRes.error) {
      error = eventsRes.error.message;
    } else if (eventsRes.data) {
      events = eventsRes.data.events;
    }

    if (statsRes.data) {
      stats = statsRes.data;
    }

    if (rulesRes.data) {
      rules = rulesRes.data.rules;
      rulesEnabled = rulesRes.data.enabled;
    }

    if (blRes.data) {
      blocklist = blRes.data;
    }

    if (crRes.data) {
      customRules = crRes.data.rules;
    }

    loading = false;
  }

  onMount(() => {
    loadData();
    return () => {
      if (bansRefreshTimer) clearInterval(bansRefreshTimer);
    };
  });

  async function loadBans() {
    bansLoading = true;
    const res = await api.listBans();
    if (res.data) {
      bans = res.data.bans;
    }
    bansLoading = false;
  }

  function startBansRefresh() {
    if (bansRefreshTimer) clearInterval(bansRefreshTimer);
    bansRefreshTimer = setInterval(loadBans, 10000);
    loadBans();
  }

  function stopBansRefresh() {
    if (bansRefreshTimer) {
      clearInterval(bansRefreshTimer);
      bansRefreshTimer = null;
    }
  }

  async function handleUnban(ip: string) {
    const res = await api.deleteBan(ip);
    if (res.data) {
      showToast(`IP ${ip} unbanned`, 'success');
      await loadBans();
    } else if (res.error) {
      showToast(res.error.message, 'error');
    }
    unbanningIp = null;
  }

  function formatDuration(seconds: number): string {
    if (seconds < 60) return `${seconds}s`;
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    if (m < 60) return `${m}m ${s}s`;
    const h = Math.floor(m / 60);
    return `${h}h ${m % 60}m`;
  }

  async function handleClear() {
    await api.clearWafEvents();
    await loadData();
  }

  function handleFilterChange() {
    loadData();
  }

  async function toggleRule(ruleId: number, enabled: boolean) {
    await api.toggleWafRule(ruleId, enabled);
    await loadData();
  }

  async function toggleBlocklist() {
    const newState = !blocklist.enabled;
    const res = await api.toggleBlocklist(newState);
    if (res.data) {
      blocklist = { ...blocklist, enabled: res.data.enabled, ip_count: res.data.ip_count };
      showToast(`Blocklist ${newState ? 'enabled' : 'disabled'}`, 'success');
      // Auto-refresh on enable to load the IP list immediately
      if (newState) {
        await reloadBlocklist();
      }
    }
  }

  function openCustomForm() {
    crId = 10000 + customRules.length;
    crDescription = '';
    crCategory = 'sql_injection';
    crPattern = '';
    crSeverity = 3;
    crError = '';
    showCustomForm = true;
  }

  async function handleCreateCustomRule() {
    if (!crDescription.trim() || !crPattern.trim()) {
      crError = 'Description and pattern are required';
      return;
    }
    crSubmitting = true;
    crError = '';
    const res = await api.createCustomRule({
      id: crId,
      description: crDescription,
      category: crCategory,
      pattern: crPattern,
      severity: crSeverity,
    });
    crSubmitting = false;
    if (res.error) {
      crError = res.error.message;
    } else {
      showToast('Custom rule created', 'success');
      showCustomForm = false;
      await loadData();
    }
  }

  async function handleDeleteCustomRule() {
    if (!deletingCustomRule) return;
    await api.deleteCustomRule(deletingCustomRule.id);
    showToast('Custom rule deleted', 'success');
    deletingCustomRule = null;
    await loadData();
  }

  async function reloadBlocklist() {
    blocklistLoading = true;
    const res = await api.reloadBlocklist();
    blocklistLoading = false;
    if (res.data) {
      blocklist = { ...blocklist, ip_count: res.data.ip_count };
      showToast('Blocklist reloaded', 'success');
    } else if (res.error) {
      error = res.error.message;
    }
  }

  function severityClass(s: number): string {
    if (s >= 5) return 'severity-critical';
    if (s >= 4) return 'severity-high';
    if (s >= 3) return 'severity-medium';
    return 'severity-low';
  }

  function categoryLabel(cat: string): string {
    const labels: Record<string, string> = {
      sql_injection: 'SQL Injection',
      xss: 'XSS',
      path_traversal: 'Path Traversal',
      command_injection: 'Cmd Injection',
      protocol_violation: 'Protocol',
    };
    return labels[cat] ?? cat;
  }

  function formatTime(ts: string): string {
    try {
      const d = new Date(ts);
      return d.toLocaleTimeString();
    } catch {
      return ts;
    }
  }
</script>

<div class="security-page">
  <div class="page-header">
    <h1>Security</h1>
    <div class="header-actions">
      <button class="btn btn-secondary" onclick={loadData}>Refresh</button>
      {#if activeTab === 'events' && events.length > 0}
        <button class="btn btn-danger" onclick={() => (showClearConfirm = true)}>Clear Events</button>
      {/if}
    </div>
  </div>

  {#if error}
    <div class="error-banner">{error}</div>
  {/if}

  <!-- Stats cards -->
  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-value">{rulesEnabled}/{stats.rule_count}</div>
      <div class="stat-label">Rules Enabled</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{stats.total_events}</div>
      <div class="stat-label">Total Events</div>
    </div>
    {#each stats.by_category as cat}
      <div class="stat-card">
        <div class="stat-value">{cat.count}</div>
        <div class="stat-label">{categoryLabel(cat.category)}</div>
      </div>
    {/each}
  </div>

  <!-- Tabs -->
  <div class="tabs">
    <button class="tab" class:active={activeTab === 'events'} onclick={() => { stopBansRefresh(); activeTab = 'events'; }}>Events</button>
    <button class="tab" class:active={activeTab === 'rules'} onclick={() => { stopBansRefresh(); activeTab = 'rules'; }}>Rules</button>
    <button class="tab" class:active={activeTab === 'custom'} onclick={() => { stopBansRefresh(); activeTab = 'custom'; }}>
      Custom Rules
      {#if customRules.length > 0}
        <span class="tab-badge-on">{customRules.length}</span>
      {/if}
    </button>
    <button class="tab" class:active={activeTab === 'blocklist'} onclick={() => { stopBansRefresh(); activeTab = 'blocklist'; }}>
      IP Blocklist
      {#if blocklist.enabled}
        <span class="tab-badge-on">ON</span>
      {:else}
        <span class="tab-badge-off">OFF</span>
      {/if}
    </button>
    <button class="tab" class:active={activeTab === 'bans'} onclick={() => { activeTab = 'bans'; startBansRefresh(); }}>
      Bans
      {#if bans.length > 0}
        <span class="tab-badge-on">{bans.length}</span>
      {/if}
    </button>
  </div>

  {#if activeTab === 'events'}
    <!-- Filter -->
    <div class="filter-bar">
      <label for="cat-filter">Filter by category:</label>
      <select id="cat-filter" bind:value={filterCategory} onchange={handleFilterChange}>
        <option value="">All categories</option>
        <option value="sql_injection">SQL Injection</option>
        <option value="xss">XSS</option>
        <option value="path_traversal">Path Traversal</option>
        <option value="command_injection">Command Injection</option>
        <option value="protocol_violation">Protocol Violation</option>
      </select>
    </div>

    <!-- Events table -->
    {#if loading}
      <p class="loading">Loading...</p>
    {:else if events.length === 0}
      <div class="empty-state">
        <p>No WAF events recorded.</p>
        <p class="text-muted">Enable WAF on a route to start monitoring for attacks.</p>
      </div>
    {:else}
      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Rule</th>
              <th>Category</th>
              <th>Severity</th>
              <th>Field</th>
              <th>Matched</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            {#each events as event}
              <tr>
                <td class="mono">{formatTime(event.timestamp)}</td>
                <td class="mono">{event.rule_id}</td>
                <td><span class="category-badge">{categoryLabel(event.category)}</span></td>
                <td><span class={severityClass(event.severity)}>{event.severity}/5</span></td>
                <td class="mono">{event.matched_field}</td>
                <td class="mono matched-value" title={event.matched_value}>{event.matched_value}</td>
                <td>{event.description}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {:else if activeTab === 'rules'}
    <!-- Rules table -->
    {#if loading}
      <p class="loading">Loading...</p>
    {:else}
      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Category</th>
              <th>Severity</th>
              <th>Description</th>
              <th>Enabled</th>
            </tr>
          </thead>
          <tbody>
            {#each rules as rule}
              <tr class:disabled-rule={!rule.enabled}>
                <td class="mono">{rule.id}</td>
                <td><span class="category-badge">{categoryLabel(rule.category)}</span></td>
                <td><span class={severityClass(rule.severity)}>{rule.severity}/5</span></td>
                <td>{rule.description}</td>
                <td>
                  <label class="toggle">
                    <input type="checkbox" checked={rule.enabled} onchange={() => toggleRule(rule.id, !rule.enabled)} />
                    <span class="toggle-slider"></span>
                  </label>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {:else if activeTab === 'custom'}
    <div class="custom-header">
      <p class="text-muted">User-defined WAF rules with custom regex patterns.</p>
      <button class="btn btn-primary" onclick={openCustomForm}>+ Add Rule</button>
    </div>

    {#if customRules.length === 0}
      <div class="empty-state">
        <p>No custom WAF rules defined.</p>
        <button class="btn btn-primary" onclick={openCustomForm}>Create your first rule</button>
      </div>
    {:else}
      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Category</th>
              <th>Severity</th>
              <th>Description</th>
              <th>Pattern</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#each customRules as rule}
              <tr>
                <td class="mono">{rule.id}</td>
                <td><span class="category-badge">{categoryLabel(rule.category)}</span></td>
                <td><span class={severityClass(rule.severity)}>{rule.severity}/5</span></td>
                <td>{rule.description}</td>
                <td class="mono matched-value" title={rule.pattern}>{rule.pattern}</td>
                <td>
                  <button class="btn-icon btn-icon-danger" onclick={() => (deletingCustomRule = rule)} title="Delete">
                    {@html trashIcon}
                  </button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}

    {#if deletingCustomRule}
      <ConfirmDialog
        title="Delete Custom Rule"
        message="Delete rule #{deletingCustomRule.id} '{deletingCustomRule.description}'?"
        confirmLabel="Delete"
        onconfirm={handleDeleteCustomRule}
        oncancel={() => (deletingCustomRule = null)}
      />
    {/if}

    {#if showCustomForm}
      <div class="overlay" role="dialog" onclick={(e) => { if (e.target === e.currentTarget) showCustomForm = false; }}>
        <div class="modal">
          <h2>Add Custom WAF Rule</h2>
          {#if crError}
            <div class="form-error">{crError}</div>
          {/if}

          <div class="form-row">
            <div class="form-group">
              <label>Rule ID</label>
              <input type="number" bind:value={crId} min="10000" />
            </div>
            <div class="form-group">
              <label>Severity (1-5)</label>
              <input type="number" bind:value={crSeverity} min="1" max="5" />
            </div>
          </div>

          <div class="form-group">
            <label>Category</label>
            <select bind:value={crCategory}>
              <option value="sql_injection">SQL Injection</option>
              <option value="xss">XSS</option>
              <option value="path_traversal">Path Traversal</option>
              <option value="command_injection">Command Injection</option>
              <option value="protocol_violation">Protocol Violation</option>
            </select>
          </div>

          <div class="form-group">
            <label>Description <span class="required">*</span></label>
            <input type="text" bind:value={crDescription} placeholder="Block known exploit pattern" />
          </div>

          <div class="form-group">
            <label>Regex Pattern <span class="required">*</span></label>
            <input type="text" bind:value={crPattern} placeholder="(?i)malicious_pattern" />
            <span class="hint">Rust regex syntax. Case-insensitive with (?i) prefix.</span>
          </div>

          <div class="form-actions">
            <button class="btn btn-cancel" onclick={() => (showCustomForm = false)}>Cancel</button>
            <button class="btn btn-primary" onclick={handleCreateCustomRule} disabled={crSubmitting}>
              {crSubmitting ? 'Creating...' : 'Create Rule'}
            </button>
          </div>
        </div>
      </div>
    {/if}

  {:else if activeTab === 'blocklist'}
    <div class="blocklist-section">
      <div class="blocklist-card">
        <div class="blocklist-header">
          <div>
            <h3>IPv4 Blocklist</h3>
            <p class="text-muted">Blocks known malicious IP addresses from accessing the proxy. Sourced from Data-Shield and refreshed every 6 hours.</p>
          </div>
          <label class="toggle">
            <input type="checkbox" checked={blocklist.enabled} onchange={toggleBlocklist} />
            <span class="toggle-slider"></span>
          </label>
        </div>

        <div class="blocklist-stats">
          <div class="blocklist-stat">
            <span class="blocklist-stat-value">{blocklist.ip_count.toLocaleString()}</span>
            <span class="blocklist-stat-label">Blocked IPs</span>
          </div>
          <div class="blocklist-stat">
            <span class="blocklist-stat-value">{blocklist.enabled ? 'Active' : 'Disabled'}</span>
            <span class="blocklist-stat-label">Status</span>
          </div>
        </div>

        <div class="blocklist-source">
          <span class="source-label">Source:</span>
          <a href={blocklist.source} target="_blank" rel="noopener noreferrer" class="mono">{blocklist.source}</a>
        </div>

        <div class="blocklist-actions">
          <button class="btn btn-secondary" onclick={reloadBlocklist} disabled={blocklistLoading || !blocklist.enabled}>
            {blocklistLoading ? 'Reloading...' : 'Reload Now'}
          </button>
        </div>
      </div>
    </div>
  {:else if activeTab === 'bans'}
    <div class="bans-section">
      <p class="text-muted">
        IPs automatically banned for repeated rate limit violations. Bans expire after 1 hour.
        Auto-refreshes every 10 seconds.
      </p>

      {#if bansLoading && bans.length === 0}
        <p class="loading">Loading...</p>
      {:else if bans.length === 0}
        <div class="empty-state">
          <p>No IPs currently banned.</p>
          <p class="text-muted">IPs are auto-banned when they exceed rate limits repeatedly.</p>
        </div>
      {:else}
        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Banned</th>
                <th>Expires In</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {#each bans as ban}
                <tr>
                  <td class="mono">{ban.ip}</td>
                  <td>{formatDuration(ban.banned_seconds_ago)} ago</td>
                  <td>{formatDuration(ban.remaining_seconds)}</td>
                  <td>
                    <button
                      class="btn btn-danger btn-sm"
                      onclick={() => (unbanningIp = ban.ip)}
                    >Unban</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>

    {#if unbanningIp}
      <ConfirmDialog
        title="Unban IP"
        message="Remove {unbanningIp} from the ban list? This IP will be able to send requests again immediately."
        confirmLabel="Unban"
        onconfirm={() => { if (unbanningIp) handleUnban(unbanningIp); }}
        oncancel={() => (unbanningIp = null)}
      />
    {/if}
  {/if}

  {#if showClearConfirm}
    <ConfirmDialog
      title="Clear Events"
      message="This will permanently delete all security events. This action cannot be undone."
      confirmLabel="Clear"
      onconfirm={() => { showClearConfirm = false; handleClear(); }}
      oncancel={() => (showClearConfirm = false)}
    />
  {/if}
</div>

<script lang="ts" module>
  const trashIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>';
</script>

<style>
  .security-page {
    max-width: none;
  }

  .page-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1.5rem;
  }

  .page-header h1 {
    margin: 0;
  }

  .header-actions {
    display: flex;
    gap: 0.5rem;
  }

  .error-banner {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid var(--color-red);
    border-radius: 0.5rem;
    color: var(--color-red);
    padding: 0.75rem 1rem;
    margin-bottom: 1rem;
  }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
    gap: 1rem;
    margin-bottom: 1.5rem;
  }

  .stat-card {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: 0.5rem;
    padding: 1rem;
    text-align: center;
  }

  .stat-value {
    font-size: 1.75rem;
    font-weight: 700;
    color: var(--color-text-heading);
  }

  .stat-label {
    font-size: 0.75rem;
    color: var(--color-text-muted);
    margin-top: 0.25rem;
  }

  .tabs {
    display: flex;
    gap: 0;
    margin-bottom: 1rem;
    border-bottom: 1px solid var(--color-border);
  }

  .tab {
    padding: 0.5rem 1.25rem;
    border: none;
    background: none;
    color: var(--color-text-muted);
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
  }

  .tab.active {
    color: var(--color-text-heading);
    border-bottom-color: var(--color-primary, #3b82f6);
  }

  .tab:hover {
    color: var(--color-text);
  }

  .filter-bar {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 1rem;
    font-size: 0.875rem;
  }

  .filter-bar label {
    color: var(--color-text-muted);
  }

  .filter-bar select {
    padding: 0.375rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
  }

  .loading {
    color: var(--color-text-muted);
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.5rem;
    padding: 3rem 0;
    color: var(--color-text-muted);
  }

  .text-muted {
    color: var(--color-text-muted);
    font-size: 0.875rem;
  }

  .table-wrapper {
    overflow-x: auto;
  }

  table {
    width: 100%;
    border-collapse: collapse;
  }

  th {
    text-align: left;
    padding: 0.5rem 0.75rem;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--color-text-muted);
    border-bottom: 1px solid var(--color-border);
  }

  td {
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--color-border);
    font-size: 0.8125rem;
    vertical-align: middle;
  }

  tr:hover td {
    background: rgba(255, 255, 255, 0.02);
  }

  .disabled-rule td {
    opacity: 0.5;
  }

  .mono {
    font-family: var(--mono);
    font-size: 0.75rem;
  }

  .matched-value {
    max-width: 200px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .category-badge {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 500;
    background: rgba(251, 146, 60, 0.1);
    color: var(--color-orange, #fb923c);
  }

  .severity-critical {
    color: var(--color-red);
    font-weight: 600;
  }

  .severity-high {
    color: var(--color-orange, #fb923c);
    font-weight: 500;
  }

  .severity-medium {
    color: var(--color-yellow, #eab308);
  }

  .severity-low {
    color: var(--color-text-muted);
  }

  .toggle {
    position: relative;
    display: inline-block;
    width: 36px;
    height: 20px;
    cursor: pointer;
  }

  .toggle input {
    opacity: 0;
    width: 0;
    height: 0;
  }

  .toggle-slider {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: var(--color-border);
    border-radius: 20px;
    transition: background 0.2s;
  }

  .toggle-slider::before {
    content: '';
    position: absolute;
    width: 16px;
    height: 16px;
    left: 2px;
    bottom: 2px;
    background: white;
    border-radius: 50%;
    transition: transform 0.2s;
  }

  .toggle input:checked + .toggle-slider {
    background: var(--color-green, #22c55e);
  }

  .toggle input:checked + .toggle-slider::before {
    transform: translateX(16px);
  }

  .btn {
    padding: 0.5rem 1rem;
    border-radius: 0.375rem;
    font-weight: 500;
    border: none;
    font-size: 0.875rem;
    cursor: pointer;
  }

  .btn-secondary {
    background: var(--color-bg-input);
    color: var(--color-text);
  }

  .btn-secondary:hover {
    background: var(--color-bg-hover);
  }

  .btn-danger {
    background: rgba(239, 68, 68, 0.1);
    color: var(--color-red);
    border: 1px solid var(--color-red);
  }

  .btn-danger:hover {
    background: rgba(239, 68, 68, 0.2);
  }

  /* Tab badges */
  .tab-badge-on {
    display: inline-block;
    padding: 0.0625rem 0.375rem;
    border-radius: var(--radius-full);
    font-size: var(--text-xs);
    font-weight: 600;
    background: var(--color-green-subtle);
    color: var(--color-green);
    margin-left: 0.375rem;
  }

  .tab-badge-off {
    display: inline-block;
    padding: 0.0625rem 0.375rem;
    border-radius: var(--radius-full);
    font-size: var(--text-xs);
    font-weight: 600;
    background: rgba(100, 116, 139, 0.1);
    color: var(--color-text-muted);
    margin-left: 0.375rem;
  }

  /* Blocklist */
  .blocklist-section {
    padding-top: var(--space-4);
  }

  .blocklist-card {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-xl);
    padding: var(--space-6);
    box-shadow: var(--shadow-sm);
    max-width: 600px;
  }

  .blocklist-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: var(--space-4);
    margin-bottom: var(--space-6);
  }

  .blocklist-header h3 {
    margin: 0 0 var(--space-1);
  }

  .blocklist-header p {
    margin: 0;
    font-size: var(--text-base);
    line-height: 1.5;
  }

  .blocklist-stats {
    display: flex;
    gap: var(--space-8);
    margin-bottom: var(--space-5);
    padding: var(--space-4);
    background: var(--color-bg-hover);
    border-radius: var(--radius-lg);
  }

  .blocklist-stat {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .blocklist-stat-value {
    font-size: var(--text-lg);
    font-weight: 700;
    font-family: var(--mono);
    color: var(--color-text-heading);
  }

  .blocklist-stat-label {
    font-size: var(--text-sm);
    color: var(--color-text-muted);
  }

  .blocklist-source {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin-bottom: var(--space-5);
    font-size: var(--text-base);
  }

  .source-label {
    color: var(--color-text-muted);
    font-weight: 500;
  }

  .blocklist-actions {
    display: flex;
    gap: var(--space-3);
  }

  /* Custom rules */
  .custom-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: var(--space-4);
  }

  .custom-header p {
    margin: 0;
  }

  /* Bans */
  .bans-section {
    padding-top: var(--space-4);
  }

  .bans-section > .text-muted {
    margin-bottom: var(--space-4);
  }

  .btn-sm {
    padding: 0.25rem 0.625rem;
    font-size: 0.75rem;
  }
</style>
