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

  // Helper / getting started guide
  const HELPER_KEY = 'lorica_helper_dismissed';
  let helperDismissed = $state(localStorage.getItem(HELPER_KEY) === 'true');
  let expandedHelpers: Record<string, boolean> = $state({});

  function dismissHelper() {
    helperDismissed = true;
    localStorage.setItem(HELPER_KEY, 'true');
  }

  function toggleHelperDetail(key: string) {
    expandedHelpers[key] = !expandedHelpers[key];
  }

  // Auto-check setup steps based on live data
  let setupSteps = $derived.by(() => {
    if (!status) return [];
    return [
      {
        key: 'backend',
        done: status.backends_count > 0,
        label: 'Add a backend',
        summary: 'Your application server that Lorica will forward traffic to.',
        detail: 'A backend is the actual server running your application (e.g. 10.0.0.5:8080). Lorica acts as a middleman between your users and your backends, forwarding requests and returning responses. You can add multiple backends per route for load balancing and failover.',
        route: '/backends',
      },
      {
        key: 'route',
        done: status.routes_count > 0,
        label: 'Create a route',
        summary: 'Map a hostname to one or more backends.',
        detail: 'A route tells Lorica: "when someone visits app.example.com, send them to backend 10.0.0.5:8080". You define the hostname, path prefix, and which backends should receive traffic. Routes support load balancing strategies (round-robin, peak EWMA, consistent hash) and health-aware failover.',
        route: '/routes',
      },
      {
        key: 'certificate',
        done: status.certificates_count > 0,
        label: 'Set up TLS certificates',
        summary: 'Enable HTTPS for your routes.',
        detail: 'TLS certificates encrypt traffic between your users and Lorica (HTTPS). You can upload your own certificates, generate self-signed ones for testing, or provision free Let\'s Encrypt certificates automatically via HTTP-01 or DNS-01 challenges. Assign a certificate to a route to enable HTTPS.',
        route: '/certificates',
      },
      {
        key: 'waf',
        done: (wafStats?.rule_count ?? 0) > 0 && status.routes_count > 0,
        label: 'Enable WAF protection',
        summary: 'Protect your routes against common web attacks.',
        detail: 'The Web Application Firewall (WAF) inspects incoming requests for SQL injection, XSS, path traversal, SSRF, Log4Shell, and other attacks. Enable it per route in detection mode (log only) or blocking mode (reject with 403). Lorica includes 28 built-in rules inspired by OWASP Core Rule Set.',
        route: '/routes',
      },
      {
        key: 'ratelimit',
        done: status.routes_count > 0,
        label: 'Configure rate limiting',
        summary: 'Prevent abuse by limiting requests per IP.',
        detail: 'Rate limiting caps the number of requests a single IP can make per second to a route. Exceeding the limit returns 429 Too Many Requests. Repeated offenders are auto-banned temporarily. Configure per-route via rate_limit_rps and rate_limit_burst. Also supports global flood defense that halves all limits under extreme load.',
        route: '/routes',
      },
      {
        key: 'blocklist',
        done: (bans?.total ?? 0) >= 0,
        label: 'Enable IP blocklist',
        summary: 'Block 80k+ known malicious IPs automatically.',
        detail: 'The IPv4 blocklist contains 80,000+ IPs flagged for scanning, brute-force, and botnet activity (updated every 6 hours from Data-Shield). Blocked IPs receive 403 before any route lookup or WAF evaluation. Toggle it on the Security page. You can also manually ban/unban individual IPs.',
        route: '/security',
      },
      {
        key: 'logs',
        done: true,
        label: 'Monitor access logs',
        summary: 'Watch real-time traffic flowing through Lorica.',
        detail: 'The Logs page shows live access logs streamed via WebSocket. Each entry shows the client IP, method, path, status code, latency, and which route/backend handled the request. Use filters to find specific requests. In worker mode, logs are forwarded from all workers to the supervisor in real-time.',
        route: '/logs',
      },
      {
        key: 'sla',
        done: true,
        label: 'Track SLA and performance',
        summary: 'Monitor uptime, latency, and error rates per route.',
        detail: 'SLA monitoring collects metrics from real traffic: success rate, average/p50/p95/p99 latency, and total requests. Data is aggregated in 1-minute buckets with rolling windows (1h, 24h, 7d, 30d). Set a target SLA per route and get alerted when it drops below. Export data as CSV or JSON.',
        route: '/sla',
      },
      {
        key: 'probes',
        done: probes.length > 0,
        label: 'Set up active probes',
        summary: 'Synthetic health checks independent of real traffic.',
        detail: 'Active probes send HTTP requests to your backends at regular intervals (e.g. every 30s). Unlike passive SLA which only measures real user traffic, probes detect problems before users are affected - useful for low-traffic routes or scheduled maintenance windows.',
        route: '/probes',
      },
      {
        key: 'system',
        done: true,
        label: 'Review system settings',
        summary: 'Workers, notifications, global limits, and more.',
        detail: 'The Settings page lets you configure notification channels (email, webhook) for alerts like backend down or certificate expiring. Global settings include max connections, flood defense threshold, and default topology. The System page shows worker health, CPU/memory, and process metrics.',
        route: '/settings',
      },
    ];
  });

  interface HelperTip {
    key: string;
    title: string;
    description: string;
  }

  const sectionHelpers: Record<string, HelperTip> = {
    system: {
      key: 'system',
      title: 'System',
      description: 'Real-time health of the Lorica process: uptime, active proxy connections, CPU and memory usage. In worker mode, each worker handles traffic independently for better performance on multi-core servers.',
    },
    routes: {
      key: 'routes',
      title: 'Routes & Backends',
      description: 'Routes map incoming hostnames to backend servers. Backends are your application servers (IP:port). Health checks monitor backend availability - degraded means slow (>2s), down means unreachable. Lorica automatically excludes unhealthy backends from rotation.',
    },
    certificates: {
      key: 'certificates',
      title: 'Certificates',
      description: 'TLS certificates for HTTPS. "Expiring Soon" warns you before certificates expire so you can renew them. Lorica supports automatic renewal via Let\'s Encrypt ACME protocol (HTTP-01 and DNS-01 challenges).',
    },
    security: {
      key: 'security',
      title: 'Security',
      description: 'WAF events show detected or blocked attacks. Active bans are IPs temporarily blocked by the auto-ban system (triggered when an IP exceeds the rate limit threshold repeatedly). You can configure per-route rate limiting, IP allowlists/denylists, and an IPv4 blocklist with 80k+ known malicious IPs.',
    },
    performance: {
      key: 'performance',
      title: 'Performance',
      description: 'SLA monitoring tracks request success rate and latency from real traffic (passive) or synthetic probes (active). Cache hit rate shows how often Lorica serves responses from its built-in HTTP cache instead of hitting your backends. Higher is better - configure caching per route.',
    },
    monitoring: {
      key: 'monitoring',
      title: 'Monitoring',
      description: 'Active probes are synthetic health checks that Lorica sends to your backends at regular intervals, independent of real traffic. Useful to detect issues before users are affected. Workers show the process isolation status in multi-worker mode.',
    },
  };

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

    <!-- GETTING STARTED GUIDE -->
    {#if !helperDismissed}
      <div class="helper-banner">
        <div class="helper-banner-header">
          <div>
            <h2>Welcome to Lorica</h2>
            <p class="helper-subtitle">A reverse proxy sits between your users and your application servers. It handles TLS, load balancing, caching, rate limiting, and security - so your apps don't have to. Follow these steps to get started:</p>
          </div>
          <button class="btn-close" onclick={dismissHelper} title="Dismiss" aria-label="Dismiss guide">&times;</button>
        </div>
        <ol class="setup-steps">
          {#each setupSteps as step (step.key)}
            <li class="setup-step" class:done={step.done}>
              <div class="step-row">
                <span class="step-check">{step.done ? '\u2713' : '\u25CB'}</span>
                <div class="step-content">
                  <button class="step-toggle" onclick={() => toggleHelperDetail(step.key)}>
                    <strong>{step.label}</strong>
                    <span class="step-summary">{step.summary}</span>
                    <span class="chevron" class:expanded={expandedHelpers[step.key]}></span>
                  </button>
                  {#if expandedHelpers[step.key]}
                    <p class="step-detail">{step.detail}</p>
                  {/if}
                </div>
                <button class="btn btn-small" onclick={() => navigate(step.route)}>Go</button>
              </div>
            </li>
          {/each}
        </ol>
        <label class="dismiss-label">
          <input type="checkbox" onchange={dismissHelper} />
          Don't show this again
        </label>
      </div>
    {/if}

    <!-- SYSTEM -->
    <div class="section-group">
      <div class="section-header-row">
        <button class="section-header" onclick={() => navigate('/system')}>
          <h2>System</h2>
          <span class="section-link">View details</span>
        </button>
        {#if !helperDismissed}
          <button class="helper-toggle" class:active={expandedHelpers['section-system']} onclick={() => toggleHelperDetail('section-system')} title="What is this?">?</button>
        {/if}
      </div>
      {#if expandedHelpers['section-system']}
        <p class="section-helper-text">{sectionHelpers.system.description}</p>
      {/if}
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
    </div>

    <!-- ROUTES & BACKENDS -->
    <div class="section-group">
      <div class="section-header-row">
        <button class="section-header" onclick={() => navigate('/routes')}>
          <h2>Routes & Backends</h2>
          <span class="section-link">Manage</span>
        </button>
        {#if !helperDismissed}
          <button class="helper-toggle" class:active={expandedHelpers['section-routes']} onclick={() => toggleHelperDetail('section-routes')} title="What is this?">?</button>
        {/if}
      </div>
      {#if expandedHelpers['section-routes']}
        <p class="section-helper-text">{sectionHelpers.routes.description}</p>
      {/if}
      <div class="card-grid">
        {#if status}
          <Card title="Routes" value={status.routes_count} color={status.routes_count === 0 ? 'orange' : 'default'} />
          <Card title="Backends" value={status.backends_count} color={status.backends_count === 0 ? 'orange' : 'default'} />
          <Card
            title="Backends Healthy"
            value={status.backends_healthy}
            color={status.backends_count > 0 ? (status.backends_healthy > 0 ? 'green' : 'red') : 'default'}
          />
          <Card
            title="Backends Degraded"
            value={status.backends_degraded}
            color={status.backends_degraded > 0 ? 'orange' : 'default'}
          />
          <Card
            title="Backends Down"
            value={status.backends_down}
            color={status.backends_count > 0 ? (status.backends_down > 0 ? 'red' : 'green') : 'default'}
          />
        {/if}
      </div>
    </div>

    <!-- CERTIFICATES -->
    <div class="section-group">
      <div class="section-header-row">
        <button class="section-header" onclick={() => navigate('/certificates')}>
          <h2>Certificates</h2>
          <span class="section-link">Manage</span>
        </button>
        {#if !helperDismissed}
          <button class="helper-toggle" class:active={expandedHelpers['section-certs']} onclick={() => toggleHelperDetail('section-certs')} title="What is this?">?</button>
        {/if}
      </div>
      {#if expandedHelpers['section-certs']}
        <p class="section-helper-text">{sectionHelpers.certificates.description}</p>
      {/if}
      <div class="card-grid">
        {#if status}
          <Card title="Total" value={status.certificates_count} color={status.certificates_count === 0 ? 'orange' : 'default'} />
          <Card
            title="Expiring Soon"
            value={status.certificates_expiring_soon}
            color={status.certificates_expiring_soon > 0 ? 'orange' : 'green'}
          />
        {/if}
      </div>
    </div>

    <!-- SECURITY -->
    <div class="section-group">
      <div class="section-header-row">
        <button class="section-header" onclick={() => navigate('/security')}>
          <h2>Security</h2>
          <span class="section-link">View details</span>
        </button>
        {#if !helperDismissed}
          <button class="helper-toggle" class:active={expandedHelpers['section-security']} onclick={() => toggleHelperDetail('section-security')} title="What is this?">?</button>
        {/if}
      </div>
      {#if expandedHelpers['section-security']}
        <p class="section-helper-text">{sectionHelpers.security.description}</p>
      {/if}
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
    </div>

    <!-- PERFORMANCE -->
    <div class="section-group">
      <div class="section-header-row">
        <button class="section-header" onclick={() => navigate('/sla')}>
          <h2>Performance</h2>
          <span class="section-link">View SLA</span>
        </button>
        {#if !helperDismissed}
          <button class="helper-toggle" class:active={expandedHelpers['section-perf']} onclick={() => toggleHelperDetail('section-perf')} title="What is this?">?</button>
        {/if}
      </div>
      {#if expandedHelpers['section-perf']}
        <p class="section-helper-text">{sectionHelpers.performance.description}</p>
      {/if}
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
    </div>

    <!-- MONITORING -->
    <div class="section-group">
      <div class="section-header-row">
        <button class="section-header" onclick={() => navigate('/probes')}>
          <h2>Monitoring</h2>
          <span class="section-link">View probes</span>
        </button>
        {#if !helperDismissed}
          <button class="helper-toggle" class:active={expandedHelpers['section-monitoring']} onclick={() => toggleHelperDetail('section-monitoring')} title="What is this?">?</button>
        {/if}
      </div>
      {#if expandedHelpers['section-monitoring']}
        <p class="section-helper-text">{sectionHelpers.monitoring.description}</p>
      {/if}
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

  .section-group {
    margin-top: var(--space-5);
  }

  .section-group:first-child {
    margin-top: 0;
  }

  .section-header {
    display: flex;
    align-items: baseline;
    gap: var(--space-3);
    width: 100%;
    margin-bottom: var(--space-3);
    padding: var(--space-2) var(--space-3);
    background: var(--color-bg-input);
    border: none;
    border-radius: var(--radius-md);
    cursor: pointer;
    text-align: left;
  }

  .section-header:hover .section-link {
    color: var(--color-primary);
  }

  .section-header h2 {
    margin: 0;
    font-size: 0.875rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 600;
    color: var(--color-text-heading);
  }

  .section-link {
    font-size: var(--text-xs);
    color: var(--color-text-muted);
    transition: color var(--transition-fast);
  }

  .section-link::after {
    content: ' \203A';
    font-size: 0.875rem;
  }

  .card-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: var(--space-3);
  }

  /* Helper / Getting Started banner */

  .helper-banner {
    background: var(--color-primary-subtle);
    border: 1px solid var(--color-primary);
    border-radius: var(--radius-xl);
    padding: var(--space-5);
    margin-bottom: var(--space-4);
  }

  .helper-banner-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: var(--space-4);
  }

  .helper-banner-header h2 {
    margin: 0 0 var(--space-1);
    font-size: 1.125rem;
    color: var(--color-text-heading);
  }

  .helper-subtitle {
    margin: 0;
    font-size: var(--text-md);
    color: var(--color-text-muted);
    line-height: 1.5;
  }

  .helper-banner .btn-close {
    flex-shrink: 0;
    width: 2rem;
    height: 2rem;
    border: none;
    border-radius: var(--radius-md);
    background: none;
    color: var(--color-text-muted);
    font-size: 1.25rem;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .helper-banner .btn-close:hover {
    background: var(--color-bg-hover);
    color: var(--color-text);
  }

  .setup-steps {
    list-style: none;
    padding: 0;
    margin: var(--space-4) 0 var(--space-3);
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .setup-step {
    border-radius: var(--radius-md);
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    padding: var(--space-3) var(--space-4);
  }

  .setup-step.done {
    border-left: 3px solid var(--color-green);
  }

  .step-row {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }

  .step-check {
    flex-shrink: 0;
    width: 1.25rem;
    height: 1.25rem;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.875rem;
  }

  .setup-step.done .step-check {
    color: var(--color-green);
    font-weight: 700;
  }

  .step-content {
    flex: 1;
    min-width: 0;
  }

  .step-toggle {
    display: flex;
    align-items: baseline;
    gap: var(--space-2);
    background: none;
    border: none;
    padding: 0;
    cursor: pointer;
    text-align: left;
    color: var(--color-text);
    font-size: var(--text-md);
    flex-wrap: wrap;
  }

  .step-toggle strong {
    color: var(--color-text-heading);
  }

  .step-summary {
    color: var(--color-text-muted);
    font-size: var(--text-sm);
  }

  .chevron {
    display: inline-block;
    font-size: 0.625rem;
    transition: transform var(--transition-fast);
    color: var(--color-text-muted);
  }

  .chevron::after {
    content: '\25BC';
  }

  .chevron.expanded {
    transform: rotate(180deg);
  }

  .step-detail {
    margin: var(--space-2) 0 0;
    font-size: var(--text-sm);
    color: var(--color-text-muted);
    line-height: 1.5;
  }

  .step-row .btn-small {
    flex-shrink: 0;
    padding: 0.25rem 0.75rem;
    font-size: var(--text-sm);
    border-radius: var(--radius-md);
    background: var(--color-primary);
    color: white;
    border: none;
    cursor: pointer;
    font-weight: 500;
  }

  .step-row .btn-small:hover {
    background: var(--color-primary-hover);
  }

  .dismiss-label {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-size: var(--text-sm);
    color: var(--color-text-muted);
    cursor: pointer;
  }

  .dismiss-label input {
    accent-color: var(--color-primary);
  }

  /* Section helper toggle */

  .section-header-row {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin-bottom: var(--space-3);
  }

  .section-header-row .section-header {
    margin-bottom: 0;
  }

  .helper-toggle {
    flex-shrink: 0;
    width: 1.5rem;
    height: 1.5rem;
    border-radius: 50%;
    border: 1px solid var(--color-primary);
    background: none;
    color: var(--color-primary);
    font-size: 0.75rem;
    font-weight: 700;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: background-color var(--transition-fast), color var(--transition-fast);
  }

  .helper-toggle:hover,
  .helper-toggle.active {
    background: var(--color-primary);
    color: white;
  }

  .section-helper-text {
    margin: 0 0 var(--space-3);
    padding: var(--space-3);
    font-size: var(--text-sm);
    color: var(--color-text-muted);
    line-height: 1.5;
    background: var(--color-primary-subtle);
    border-radius: var(--radius-md);
    border-left: 3px solid var(--color-primary);
  }
</style>
