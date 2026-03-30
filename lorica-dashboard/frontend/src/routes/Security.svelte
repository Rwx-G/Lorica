<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type WafEvent, type WafCategoryCount, type WafRuleSummary } from '../lib/api';

  let events: WafEvent[] = $state([]);
  let stats: { total_events: number; rule_count: number; by_category: WafCategoryCount[] } = $state({
    total_events: 0,
    rule_count: 0,
    by_category: [],
  });
  let rules: WafRuleSummary[] = $state([]);
  let rulesEnabled = $state(0);
  let loading = $state(true);
  let error = $state('');
  let filterCategory = $state('');
  let activeTab: 'events' | 'rules' = $state('events');

  async function loadData() {
    loading = true;
    error = '';
    const [eventsRes, statsRes, rulesRes] = await Promise.all([
      api.getWafEvents({ limit: 100, category: filterCategory || undefined }),
      api.getWafStats(),
      api.getWafRules(),
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

    loading = false;
  }

  onMount(loadData);

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
        <button class="btn btn-danger" onclick={handleClear}>Clear Events</button>
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
    <button class="tab" class:active={activeTab === 'events'} onclick={() => activeTab = 'events'}>Events</button>
    <button class="tab" class:active={activeTab === 'rules'} onclick={() => activeTab = 'rules'}>Rules</button>
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
  {:else}
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
  {/if}
</div>

<style>
  .security-page {
    max-width: 1200px;
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
</style>
