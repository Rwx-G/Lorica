<script lang="ts">
  import { onMount } from 'svelte';
  import { navigate } from '../lib/router';
  import {
    api,
    type StatusResponse,
    type SystemResponse,
    type WafStatsResponse,
    type SlaSummary,
    type CacheStatsResponse,
    type BanListResponse,
    type WorkerStatus,
    type ProbeConfigResponse,
  } from '../lib/api';
  import Card from '../components/Card.svelte';

  let status: StatusResponse | null = $state(null);
  let system: SystemResponse | null = $state(null);
  let wafStats: WafStatsResponse | null = $state(null);
  let slaSummaries: SlaSummary[] = $state([]);
  let cacheStats: CacheStatsResponse | null = $state(null);
  let bans: BanListResponse | null = $state(null);
  let workers: WorkerStatus[] = $state([]);
  let probes: ProbeConfigResponse[] = $state([]);
  let error = $state('');
  let loading = $state(true);
  let refreshTimer: ReturnType<typeof setInterval> | null = null;
  let lastRefresh: Date | null = $state(null);

  function formatUptime(seconds: number): string {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  }

  function formatBytes(bytes: number): string {
    if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(1)} GB`;
    if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(0)} MB`;
    return `${(bytes / 1024).toFixed(0)} KB`;
  }

  function cpuColor(pct: number): 'default' | 'green' | 'orange' | 'red' {
    if (pct >= 90) return 'red';
    if (pct >= 70) return 'orange';
    return 'green';
  }

  function memColor(pct: number): 'default' | 'green' | 'orange' | 'red' {
    if (pct >= 90) return 'red';
    if (pct >= 80) return 'orange';
    return 'default';
  }

  // Computed SLA aggregates
  let avgSla = $derived.by(() => {
    const hourly = slaSummaries.filter(s => s.window === '1h' && s.total_requests > 0);
    if (hourly.length === 0) return null;
    return hourly.reduce((sum, s) => sum + s.sla_pct, 0) / hourly.length;
  });

  let avgLatency = $derived.by(() => {
    const hourly = slaSummaries.filter(s => s.window === '1h' && s.total_requests > 0);
    if (hourly.length === 0) return null;
    return hourly.reduce((sum, s) => sum + s.avg_latency_ms, 0) / hourly.length;
  });

  let slaBreaches = $derived.by(() => {
    return slaSummaries.filter(s => s.window === '1h' && !s.meets_target && s.total_requests > 0).length;
  });

  let totalRequests1h = $derived.by(() => {
    return slaSummaries
      .filter(s => s.window === '1h')
      .reduce((sum, s) => sum + s.total_requests, 0);
  });

  let workersHealthy = $derived(workers.filter(w => w.healthy).length);
  let workersUnhealthy = $derived(workers.filter(w => !w.healthy).length);
  let probesEnabled = $derived(probes.filter(p => p.enabled).length);

  let wafTopCategory = $derived.by(() => {
    if (!wafStats || wafStats.by_category.length === 0) return null;
    const sorted = [...wafStats.by_category].sort((a, b) => b.count - a.count);
    return sorted[0];
  });

  async function fetchAll() {
    try {
      const [statusRes, systemRes, wafRes, slaRes, cacheRes, bansRes, workersRes, probesRes] =
        await Promise.all([
          api.getStatus(),
          api.getSystem(),
          api.getWafStats(),
          api.getSlaOverview(),
          api.getCacheStats(),
          api.listBans(),
          api.getWorkers(),
          api.listProbes(),
        ]);

      if (statusRes.error) {
        error = statusRes.error.message;
        return;
      }

      status = statusRes.data ?? null;
      system = systemRes.data ?? null;
      wafStats = wafRes.data ?? null;
      slaSummaries = (slaRes.data as SlaSummary[]) ?? [];
      cacheStats = cacheRes.data ?? null;
      bans = bansRes.data ?? null;
      workers = workersRes.data?.workers ?? [];
      probes = (probesRes.data as ProbeConfigResponse[]) ?? [];
      error = '';
      lastRefresh = new Date();
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to load dashboard data';
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    fetchAll();
    refreshTimer = setInterval(fetchAll, 30000);
    return () => {
      if (refreshTimer) clearInterval(refreshTimer);
    };
  });
</script>

<div class="overview">
  <div class="overview-header">
    <h1>Overview</h1>
    {#if lastRefresh}
      <span class="refresh-indicator" title="Auto-refresh every 30s">
        <span class="refresh-dot"></span>
        Last update: {lastRefresh.toLocaleTimeString()}
      </span>
    {/if}
  </div>

  {#if error}
    <div class="error-banner">{error}</div>
  {:else if loading}
    <p class="loading">Loading dashboard...</p>
  {:else}

    <!-- SYSTEM -->
    <button class="section-header" onclick={() => navigate('/system')}>
      <h2>System</h2>
      <span class="section-link">View details</span>
    </button>
    <div class="card-grid">
      {#if system}
        <Card title="Uptime" value={formatUptime(system.proxy.uptime_seconds)} />
        <Card title="Active Connections" value={system.proxy.active_connections} />
        <Card
          title="CPU"
          value="{system.host.cpu_usage_percent.toFixed(1)}%"
          color={cpuColor(system.host.cpu_usage_percent)}
        />
        <Card
          title="Memory"
          value="{system.host.memory_usage_percent.toFixed(1)}%"
          color={memColor(system.host.memory_usage_percent)}
        />
      {:else}
        <Card title="System" value="-" />
      {/if}
    </div>

    <!-- ROUTES & BACKENDS -->
    <button class="section-header" onclick={() => navigate('/routes')}>
      <h2>Routes & Backends</h2>
      <span class="section-link">Manage</span>
    </button>
    <div class="card-grid">
      {#if status}
        <Card title="Routes" value={status.routes_count} />
        <Card title="Backends" value={status.backends_count} />
        <Card
          title="Healthy"
          value={status.backends_healthy}
          color={status.backends_healthy > 0 ? 'green' : 'default'}
        />
        <Card
          title="Degraded"
          value={status.backends_degraded}
          color={status.backends_degraded > 0 ? 'orange' : 'default'}
        />
        <Card
          title="Down"
          value={status.backends_down}
          color={status.backends_down > 0 ? 'red' : 'default'}
        />
      {/if}
    </div>

    <!-- CERTIFICATES -->
    <button class="section-header" onclick={() => navigate('/certificates')}>
      <h2>Certificates</h2>
      <span class="section-link">Manage</span>
    </button>
    <div class="card-grid">
      {#if status}
        <Card title="Total" value={status.certificates_count} />
        <Card
          title="Expiring Soon"
          value={status.certificates_expiring_soon}
          color={status.certificates_expiring_soon > 0 ? 'orange' : 'green'}
        />
      {/if}
    </div>

    <!-- SECURITY -->
    <button class="section-header" onclick={() => navigate('/security')}>
      <h2>Security</h2>
      <span class="section-link">View details</span>
    </button>
    <div class="card-grid">
      <Card
        title="WAF Events"
        value={wafStats?.total_events ?? 0}
        color={wafStats && wafStats.total_events > 0 ? 'orange' : 'green'}
      />
      {#if wafTopCategory}
        <Card title="Top Category" value={wafTopCategory.category} />
      {/if}
      <Card
        title="Active Bans"
        value={bans?.total ?? 0}
        color={bans && bans.total > 0 ? 'red' : 'default'}
      />
      <Card
        title="WAF Rules"
        value={wafStats?.rule_count ?? 0}
      />
    </div>

    <!-- PERFORMANCE -->
    <button class="section-header" onclick={() => navigate('/sla')}>
      <h2>Performance</h2>
      <span class="section-link">View SLA</span>
    </button>
    <div class="card-grid">
      <Card
        title="Requests (1h)"
        value={totalRequests1h.toLocaleString()}
      />
      {#if avgSla !== null}
        <Card
          title="Avg SLA (1h)"
          value="{avgSla.toFixed(2)}%"
          color={avgSla >= 99.9 ? 'green' : avgSla >= 99 ? 'orange' : 'red'}
        />
      {:else}
        <Card title="Avg SLA (1h)" value="-" />
      {/if}
      {#if avgLatency !== null}
        <Card
          title="Avg Latency (1h)"
          value="{avgLatency.toFixed(0)} ms"
          color={avgLatency <= 100 ? 'green' : avgLatency <= 500 ? 'orange' : 'red'}
        />
      {:else}
        <Card title="Avg Latency (1h)" value="-" />
      {/if}
      <Card
        title="SLA Breaches"
        value={slaBreaches}
        color={slaBreaches > 0 ? 'red' : 'green'}
      />
      <Card
        title="Cache Hit Rate"
        value={cacheStats ? `${(cacheStats.hit_rate * 100).toFixed(1)}%` : '-'}
        color={cacheStats && cacheStats.hit_rate >= 0.5 ? 'green' : 'default'}
      />
    </div>

    <!-- MONITORING -->
    <button class="section-header" onclick={() => navigate('/probes')}>
      <h2>Monitoring</h2>
      <span class="section-link">View probes</span>
    </button>
    <div class="card-grid">
      <Card title="Active Probes" value={probesEnabled} color={probesEnabled > 0 ? 'green' : 'default'} />
      <Card title="Total Probes" value={probes.length} />
      {#if workers.length > 0}
        <Card
          title="Workers"
          value={workers.length}
          color={workersUnhealthy > 0 ? 'red' : 'green'}
        />
        {#if workersUnhealthy > 0}
          <Card title="Unhealthy Workers" value={workersUnhealthy} color="red" />
        {/if}
      {:else}
        <Card title="Workers" value="Single-process" />
      {/if}
    </div>

  {/if}
</div>

<style>
  .overview {
    max-width: none;
  }

  .overview-header {
    display: flex;
    align-items: baseline;
    gap: var(--space-4);
    margin-bottom: var(--space-2);
  }

  .overview-header h1 {
    margin: 0;
  }

  .refresh-indicator {
    font-size: var(--text-xs);
    color: var(--color-text-muted);
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }

  .refresh-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--color-green);
    animation: pulse 2s ease-in-out infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }

  .section-header {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    width: 100%;
    margin-top: var(--space-6);
    margin-bottom: var(--space-3);
    padding: 0;
    background: none;
    border: none;
    cursor: pointer;
    text-align: left;
  }

  .section-header:hover .section-link {
    color: var(--color-primary);
  }

  .section-header h2 {
    margin: 0;
    font-size: 1rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--color-text-muted);
  }

  .section-link {
    font-size: var(--text-xs);
    color: var(--color-text-muted);
    transition: color var(--transition-fast);
  }

  .card-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: var(--space-4);
  }
</style>
