<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    type RouteResponse,
    type BackendResponse,
    type CertificateResponse,
    type CreateRouteRequest,
    type UpdateRouteRequest,
  } from '../lib/api';
  import StatusBadge from '../components/StatusBadge.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';

  let routes: RouteResponse[] = $state([]);
  let backends: BackendResponse[] = $state([]);
  let certificates: CertificateResponse[] = $state([]);
  let error = $state('');
  let loading = $state(true);

  // Form state
  let showForm = $state(false);
  let editingRoute: RouteResponse | null = $state(null);
  let formHostname = $state('');
  let formPathPrefix = $state('/');
  let formBackendIds: string[] = $state([]);
  let formCertificateId = $state('');
  let formLoadBalancing = $state('round_robin');
  let formTopologyType = $state('single_vm');
  let formWafEnabled = $state(false);
  let formWafMode = $state('detection');
  let formEnabled = $state(true);
  let formError = $state('');
  let formSubmitting = $state(false);

  // Advanced configuration state
  let showAdvanced = $state(false);
  let formForceHttps = $state(false);
  let formRedirectHostname = $state('');
  let formHostnameAliases = $state('');
  let formWebsocketEnabled = $state(true);
  let formAccessLogEnabled = $state(true);
  let formConnectTimeout = $state(5);
  let formReadTimeout = $state(60);
  let formSendTimeout = $state(60);
  let formStripPathPrefix = $state('');
  let formAddPathPrefix = $state('');
  let formSecurityHeaders = $state('moderate');
  let formMaxBodyMb = $state('');
  let formRateLimitRps = $state('');
  let formRateLimitBurst = $state('');
  let formIpAllowlist = $state('');
  let formIpDenylist = $state('');
  let formProxyHeaders = $state('');
  let formProxyHeadersRemove = $state('');
  let formResponseHeaders = $state('');
  let formResponseHeadersRemove = $state('');
  let formCorsOrigins = $state('');
  let formCorsMethods = $state('');
  let formCorsMaxAge = $state('');
  let formCompressionEnabled = $state(false);
  let formRetryAttempts = $state('');

  // Delete state
  let deletingRoute: RouteResponse | null = $state(null);

  const loadBalancingOptions = [
    { value: 'round_robin', label: 'Round Robin' },
    { value: 'consistent_hash', label: 'Consistent Hash' },
    { value: 'random', label: 'Random' },
    { value: 'peak_ewma', label: 'Peak EWMA' },
  ];

  const topologyOptions = [
    { value: 'single_vm', label: 'Single VM' },
    { value: 'ha', label: 'High Availability' },
    { value: 'docker_swarm', label: 'Docker Swarm' },
    { value: 'kubernetes', label: 'Kubernetes' },
    { value: 'custom', label: 'Custom' },
  ];

  async function loadData() {
    loading = true;
    error = '';
    const [routesRes, backendsRes, certsRes] = await Promise.all([
      api.listRoutes(),
      api.listBackends(),
      api.listCertificates(),
    ]);
    if (routesRes.error) {
      error = routesRes.error.message;
    } else if (routesRes.data) {
      routes = routesRes.data.routes;
    }
    if (backendsRes.data) {
      backends = backendsRes.data.backends;
    }
    if (certsRes.data) {
      certificates = certsRes.data.certificates;
    }
    loading = false;
  }

  onMount(loadData);

  function openCreateForm() {
    editingRoute = null;
    formHostname = '';
    formPathPrefix = '/';
    formBackendIds = [];
    formCertificateId = '';
    formLoadBalancing = 'round_robin';
    formTopologyType = 'single_vm';
    formWafEnabled = false;
    formWafMode = 'detection';
    formEnabled = true;
    formError = '';
    showAdvanced = false;
    formForceHttps = false;
    formRedirectHostname = '';
    formHostnameAliases = '';
    formWebsocketEnabled = true;
    formAccessLogEnabled = true;
    formConnectTimeout = 5;
    formReadTimeout = 60;
    formSendTimeout = 60;
    formStripPathPrefix = '';
    formAddPathPrefix = '';
    formSecurityHeaders = 'moderate';
    formMaxBodyMb = '';
    formRateLimitRps = '';
    formRateLimitBurst = '';
    formIpAllowlist = '';
    formIpDenylist = '';
    formProxyHeaders = '';
    formProxyHeadersRemove = '';
    formResponseHeaders = '';
    formResponseHeadersRemove = '';
    formCorsOrigins = '';
    formCorsMethods = '';
    formCorsMaxAge = '';
    formCompressionEnabled = false;
    formRetryAttempts = '';
    showForm = true;
  }

  function recordToText(rec: Record<string, string>): string {
    return Object.entries(rec).map(([k, v]) => `${k}=${v}`).join('\n');
  }

  function textToRecord(text: string): Record<string, string> {
    const result: Record<string, string> = {};
    for (const line of text.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const idx = trimmed.indexOf('=');
      if (idx > 0) {
        result[trimmed.slice(0, idx).trim()] = trimmed.slice(idx + 1).trim();
      }
    }
    return result;
  }

  function csvToArray(text: string): string[] {
    return text.split(',').map((s) => s.trim()).filter((s) => s.length > 0);
  }

  function linesToArray(text: string): string[] {
    return text.split('\n').map((s) => s.trim()).filter((s) => s.length > 0);
  }

  function openEditForm(route: RouteResponse) {
    editingRoute = route;
    formHostname = route.hostname;
    formPathPrefix = route.path_prefix;
    formBackendIds = [...route.backends];
    formCertificateId = route.certificate_id ?? '';
    formLoadBalancing = route.load_balancing;
    formTopologyType = route.topology_type;
    formWafEnabled = route.waf_enabled;
    formWafMode = route.waf_mode ?? 'detection';
    formEnabled = route.enabled;
    formError = '';
    showAdvanced = false;
    formForceHttps = route.force_https;
    formRedirectHostname = route.redirect_hostname ?? '';
    formHostnameAliases = route.hostname_aliases.join(', ');
    formWebsocketEnabled = route.websocket_enabled;
    formAccessLogEnabled = route.access_log_enabled;
    formConnectTimeout = route.connect_timeout_s;
    formReadTimeout = route.read_timeout_s;
    formSendTimeout = route.send_timeout_s;
    formStripPathPrefix = route.strip_path_prefix ?? '';
    formAddPathPrefix = route.add_path_prefix ?? '';
    formSecurityHeaders = route.security_headers;
    formMaxBodyMb = route.max_request_body_bytes != null ? String(route.max_request_body_bytes / (1024 * 1024)) : '';
    formRateLimitRps = route.rate_limit_rps != null ? String(route.rate_limit_rps) : '';
    formRateLimitBurst = route.rate_limit_burst != null ? String(route.rate_limit_burst) : '';
    formIpAllowlist = route.ip_allowlist.join('\n');
    formIpDenylist = route.ip_denylist.join('\n');
    formProxyHeaders = recordToText(route.proxy_headers);
    formProxyHeadersRemove = route.proxy_headers_remove.join(', ');
    formResponseHeaders = recordToText(route.response_headers);
    formResponseHeadersRemove = route.response_headers_remove.join(', ');
    formCorsOrigins = route.cors_allowed_origins.join(', ');
    formCorsMethods = route.cors_allowed_methods.join(', ');
    formCorsMaxAge = route.cors_max_age_s != null ? String(route.cors_max_age_s) : '';
    formCompressionEnabled = route.compression_enabled;
    formRetryAttempts = route.retry_attempts != null ? String(route.retry_attempts) : '';
    showForm = true;
  }

  function closeForm() {
    showForm = false;
    editingRoute = null;
  }

  function handleFormKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      closeForm();
    } else if (e.key === 'Enter' && !formSubmitting && (e.target as HTMLElement)?.tagName !== 'SELECT' && (e.target as HTMLElement)?.tagName !== 'TEXTAREA') {
      e.preventDefault();
      handleSubmit();
    }
  }

  async function handleSubmit() {
    if (!formHostname.trim()) {
      formError = 'Hostname is required';
      return;
    }
    formSubmitting = true;
    formError = '';

    const advancedFields = {
      force_https: formForceHttps,
      redirect_hostname: formRedirectHostname || undefined,
      hostname_aliases: csvToArray(formHostnameAliases).length > 0 ? csvToArray(formHostnameAliases) : undefined,
      websocket_enabled: formWebsocketEnabled,
      access_log_enabled: formAccessLogEnabled,
      connect_timeout_s: formConnectTimeout,
      read_timeout_s: formReadTimeout,
      send_timeout_s: formSendTimeout,
      strip_path_prefix: formStripPathPrefix || undefined,
      add_path_prefix: formAddPathPrefix || undefined,
      security_headers: formSecurityHeaders,
      max_request_body_bytes: formMaxBodyMb ? Math.round(Number(formMaxBodyMb) * 1024 * 1024) : undefined,
      rate_limit_rps: formRateLimitRps ? Number(formRateLimitRps) : undefined,
      rate_limit_burst: formRateLimitBurst ? Number(formRateLimitBurst) : undefined,
      ip_allowlist: linesToArray(formIpAllowlist).length > 0 ? linesToArray(formIpAllowlist) : undefined,
      ip_denylist: linesToArray(formIpDenylist).length > 0 ? linesToArray(formIpDenylist) : undefined,
      proxy_headers: formProxyHeaders.trim() ? textToRecord(formProxyHeaders) : undefined,
      proxy_headers_remove: csvToArray(formProxyHeadersRemove).length > 0 ? csvToArray(formProxyHeadersRemove) : undefined,
      response_headers: formResponseHeaders.trim() ? textToRecord(formResponseHeaders) : undefined,
      response_headers_remove: csvToArray(formResponseHeadersRemove).length > 0 ? csvToArray(formResponseHeadersRemove) : undefined,
      cors_allowed_origins: csvToArray(formCorsOrigins).length > 0 ? csvToArray(formCorsOrigins) : undefined,
      cors_allowed_methods: csvToArray(formCorsMethods).length > 0 ? csvToArray(formCorsMethods) : undefined,
      cors_max_age_s: formCorsMaxAge ? Number(formCorsMaxAge) : undefined,
      compression_enabled: formCompressionEnabled,
      retry_attempts: formRetryAttempts ? Number(formRetryAttempts) : undefined,
    };

    if (editingRoute) {
      const body: UpdateRouteRequest = {
        hostname: formHostname,
        path_prefix: formPathPrefix,
        backend_ids: formBackendIds,
        certificate_id: formCertificateId || undefined,
        load_balancing: formLoadBalancing,
        topology_type: formTopologyType,
        waf_enabled: formWafEnabled,
        waf_mode: formWafMode,
        enabled: formEnabled,
        ...advancedFields,
      };
      const res = await api.updateRoute(editingRoute.id, body);
      if (res.error) {
        formError = res.error.message;
        formSubmitting = false;
        return;
      }
    } else {
      const body: CreateRouteRequest = {
        hostname: formHostname,
        path_prefix: formPathPrefix || '/',
        backend_ids: formBackendIds.length > 0 ? formBackendIds : undefined,
        certificate_id: formCertificateId || undefined,
        load_balancing: formLoadBalancing,
        topology_type: formTopologyType,
        waf_enabled: formWafEnabled,
        waf_mode: formWafMode,
        ...advancedFields,
      };
      const res = await api.createRoute(body);
      if (res.error) {
        formError = res.error.message;
        formSubmitting = false;
        return;
      }
    }

    formSubmitting = false;
    closeForm();
    await loadData();
  }

  async function handleDelete() {
    if (!deletingRoute) return;
    const res = await api.deleteRoute(deletingRoute.id);
    if (res.error) {
      error = res.error.message;
    }
    deletingRoute = null;
    await loadData();
  }

  function toggleBackend(id: string) {
    if (formBackendIds.includes(id)) {
      formBackendIds = formBackendIds.filter((b) => b !== id);
    } else {
      formBackendIds = [...formBackendIds, id];
    }
  }

  function certLabel(id: string): string {
    const c = certificates.find((c) => c.id === id);
    return c ? c.domain : id.slice(0, 8);
  }

  function resolveHealthStatus(route: RouteResponse): 'healthy' | 'degraded' | 'down' | 'unknown' {
    if (route.backends.length === 0) return 'unknown';
    const statuses = route.backends.map((bid) => {
      const b = backends.find((b) => b.id === bid);
      return b?.health_status ?? 'unknown';
    });
    if (statuses.every((s) => s === 'healthy')) return 'healthy';
    if (statuses.some((s) => s === 'healthy')) return 'degraded';
    if (statuses.every((s) => s === 'down')) return 'down';
    return 'unknown';
  }
</script>

<div class="routes-page">
  <div class="page-header">
    <h1>Routes</h1>
    <button class="btn btn-primary" onclick={openCreateForm}>+ New Route</button>
  </div>

  {#if error}
    <div class="error-banner">{error}</div>
  {/if}

  {#if loading}
    <p class="loading">Loading...</p>
  {:else if routes.length === 0}
    <div class="empty-state">
      <p>No routes configured yet.</p>
      <button class="btn btn-primary" onclick={openCreateForm}>Create your first route</button>
    </div>
  {:else}
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Hostname</th>
            <th>Path</th>
            <th>Backends</th>
            <th>TLS</th>
            <th>WAF</th>
            <th>Health</th>
            <th>Enabled</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each routes as route (route.id)}
            <tr>
              <td class="hostname">{route.hostname}</td>
              <td class="mono">{route.path_prefix}</td>
              <td>
                {#if route.backends.length === 0}
                  <span class="text-muted">None</span>
                {:else}
                  <span class="backend-count">{route.backends.length} backend{route.backends.length > 1 ? 's' : ''}</span>
                {/if}
              </td>
              <td>
                {#if route.certificate_id}
                  <span class="tls-on" title={certLabel(route.certificate_id)}>TLS</span>
                {:else}
                  <span class="tls-off">-</span>
                {/if}
              </td>
              <td>
                {#if route.waf_enabled}
                  <span class="waf-on" title={route.waf_mode === 'blocking' ? 'Blocking' : 'Detection'}>{route.waf_mode === 'blocking' ? 'Block' : 'Detect'}</span>
                {:else}
                  <span class="waf-off">-</span>
                {/if}
              </td>
              <td><StatusBadge status={resolveHealthStatus(route)} /></td>
              <td>
                <span class="enabled-indicator" class:on={route.enabled} class:off={!route.enabled}>
                  {route.enabled ? 'Yes' : 'No'}
                </span>
              </td>
              <td class="actions">
                <button class="btn-icon" title="Edit" onclick={() => openEditForm(route)}>
                  {@html editIcon}
                </button>
                <button class="btn-icon btn-icon-danger" title="Delete" onclick={() => { deletingRoute = route; }}>
                  {@html trashIcon}
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

{#if showForm}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="overlay" onclick={closeForm} onkeydown={handleFormKeydown} role="dialog" aria-modal="true" tabindex="-1">
    <div class="modal" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="document">
      <h2>{editingRoute ? 'Edit Route' : 'New Route'}</h2>

      {#if formError}
        <div class="form-error">{formError}</div>
      {/if}

      <div class="form-group">
        <label for="hostname">Hostname <span class="required">*</span></label>
        <input id="hostname" type="text" bind:value={formHostname} placeholder="example.com" />
      </div>

      <div class="form-group">
        <label for="path">Path prefix</label>
        <input id="path" type="text" bind:value={formPathPrefix} placeholder="/" />
      </div>

      <div class="form-group">
        <span class="field-label">Backends</span>
        {#if backends.length === 0}
          <p class="text-muted small">No backends available</p>
        {:else}
          <div class="checkbox-list">
            {#each backends as b (b.id)}
              <label class="checkbox-item">
                <input type="checkbox" checked={formBackendIds.includes(b.id)} onchange={() => toggleBackend(b.id)} />
                <span>{b.address}</span>
                <StatusBadge status={b.health_status === 'healthy' ? 'healthy' : b.health_status === 'degraded' ? 'degraded' : b.health_status === 'down' ? 'down' : 'unknown'} />
              </label>
            {/each}
          </div>
        {/if}
      </div>

      <div class="form-group">
        <label for="certificate">TLS Certificate</label>
        <select id="certificate" bind:value={formCertificateId}>
          <option value="">None (no TLS)</option>
          {#each certificates as c (c.id)}
            <option value={c.id}>{c.domain}</option>
          {/each}
        </select>
      </div>

      <div class="form-row">
        <div class="form-group">
          <label for="lb">Load Balancing</label>
          <select id="lb" bind:value={formLoadBalancing}>
            {#each loadBalancingOptions as opt}
              <option value={opt.value}>{opt.label}</option>
            {/each}
          </select>
        </div>

        <div class="form-group">
          <label for="topo">Topology</label>
          <select id="topo" bind:value={formTopologyType}>
            {#each topologyOptions as opt}
              <option value={opt.value}>{opt.label}</option>
            {/each}
          </select>
        </div>
      </div>

      <div class="form-group">
        <label class="checkbox-item">
          <input type="checkbox" bind:checked={formWafEnabled} />
          <span>Enable WAF</span>
        </label>
      </div>

      {#if formWafEnabled}
        <div class="form-group">
          <label for="waf-mode">WAF Mode</label>
          <select id="waf-mode" bind:value={formWafMode}>
            <option value="detection">Detection (log only)</option>
            <option value="blocking">Blocking (reject 403)</option>
          </select>
        </div>
      {/if}

      {#if editingRoute}
        <div class="form-group">
          <label class="checkbox-item">
            <input type="checkbox" bind:checked={formEnabled} />
            <span>Enabled</span>
          </label>
        </div>
      {/if}

      <div class="advanced-toggle">
        <button type="button" class="btn btn-toggle" onclick={() => { showAdvanced = !showAdvanced; }}>
          <span class="toggle-arrow" class:open={showAdvanced}>{@html chevronIcon}</span>
          Advanced Configuration
        </button>
      </div>

      {#if showAdvanced}
        <div class="advanced-section">
          <h3 class="section-title">Proxy Settings</h3>
          <div class="form-group">
            <label class="checkbox-item">
              <input type="checkbox" bind:checked={formForceHttps} />
              <span>Force HTTPS redirect</span>
            </label>
          </div>
          <div class="form-group">
            <label for="redirect-hostname">Redirect hostname</label>
            <input id="redirect-hostname" type="text" bind:value={formRedirectHostname} placeholder="e.g. www.example.com" />
          </div>
          <div class="form-group">
            <label for="hostname-aliases">Hostname aliases <span class="hint">(comma-separated)</span></label>
            <input id="hostname-aliases" type="text" bind:value={formHostnameAliases} placeholder="alias1.com, alias2.com" />
          </div>
          <div class="form-group">
            <label class="checkbox-item">
              <input type="checkbox" bind:checked={formWebsocketEnabled} />
              <span>WebSocket support</span>
            </label>
          </div>
          <div class="form-group">
            <label class="checkbox-item">
              <input type="checkbox" bind:checked={formAccessLogEnabled} />
              <span>Access log enabled</span>
            </label>
          </div>

          <h3 class="section-title">Timeouts</h3>
          <div class="form-row form-row-3">
            <div class="form-group">
              <label for="connect-timeout">Connect (s)</label>
              <input id="connect-timeout" type="number" min="1" bind:value={formConnectTimeout} />
            </div>
            <div class="form-group">
              <label for="read-timeout">Read (s)</label>
              <input id="read-timeout" type="number" min="1" bind:value={formReadTimeout} />
            </div>
            <div class="form-group">
              <label for="send-timeout">Send (s)</label>
              <input id="send-timeout" type="number" min="1" bind:value={formSendTimeout} />
            </div>
          </div>

          <h3 class="section-title">Path Rewriting</h3>
          <div class="form-row">
            <div class="form-group">
              <label for="strip-path">Strip path prefix</label>
              <input id="strip-path" type="text" bind:value={formStripPathPrefix} placeholder="/api/v1" />
            </div>
            <div class="form-group">
              <label for="add-path">Add path prefix</label>
              <input id="add-path" type="text" bind:value={formAddPathPrefix} placeholder="/backend" />
            </div>
          </div>

          <h3 class="section-title">Security</h3>
          <div class="form-group">
            <label for="security-headers">Security headers preset</label>
            <select id="security-headers" bind:value={formSecurityHeaders}>
              <option value="strict">Strict</option>
              <option value="moderate">Moderate</option>
              <option value="none">None</option>
            </select>
          </div>
          <div class="form-row form-row-3">
            <div class="form-group">
              <label for="max-body">Max body (MB)</label>
              <input id="max-body" type="number" min="0" step="1" bind:value={formMaxBodyMb} placeholder="No limit" />
            </div>
            <div class="form-group">
              <label for="rate-rps">Rate limit RPS</label>
              <input id="rate-rps" type="number" min="1" bind:value={formRateLimitRps} placeholder="No limit" />
            </div>
            <div class="form-group">
              <label for="rate-burst">Rate limit burst</label>
              <input id="rate-burst" type="number" min="1" bind:value={formRateLimitBurst} placeholder="No limit" />
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label for="ip-allow">IP allowlist <span class="hint">(one per line)</span></label>
              <textarea id="ip-allow" rows="3" bind:value={formIpAllowlist} placeholder="192.168.1.0/24&#10;10.0.0.1"></textarea>
            </div>
            <div class="form-group">
              <label for="ip-deny">IP denylist <span class="hint">(one per line)</span></label>
              <textarea id="ip-deny" rows="3" bind:value={formIpDenylist} placeholder="203.0.113.0/24"></textarea>
            </div>
          </div>

          <h3 class="section-title">Headers</h3>
          <div class="form-group">
            <label for="proxy-headers">Custom proxy headers <span class="hint">(key=value, one per line)</span></label>
            <textarea id="proxy-headers" rows="3" bind:value={formProxyHeaders} placeholder="X-Forwarded-For=$remote_addr&#10;X-Custom=value"></textarea>
          </div>
          <div class="form-group">
            <label for="proxy-headers-remove">Remove proxy headers <span class="hint">(comma-separated)</span></label>
            <input id="proxy-headers-remove" type="text" bind:value={formProxyHeadersRemove} placeholder="X-Powered-By, Server" />
          </div>
          <div class="form-group">
            <label for="response-headers">Custom response headers <span class="hint">(key=value, one per line)</span></label>
            <textarea id="response-headers" rows="3" bind:value={formResponseHeaders} placeholder="X-Frame-Options=DENY&#10;Cache-Control=no-store"></textarea>
          </div>
          <div class="form-group">
            <label for="response-headers-remove">Remove response headers <span class="hint">(comma-separated)</span></label>
            <input id="response-headers-remove" type="text" bind:value={formResponseHeadersRemove} placeholder="X-Powered-By, Server" />
          </div>

          <h3 class="section-title">CORS</h3>
          <div class="form-group">
            <label for="cors-origins">Allowed origins <span class="hint">(comma-separated)</span></label>
            <input id="cors-origins" type="text" bind:value={formCorsOrigins} placeholder="https://example.com, https://app.example.com" />
          </div>
          <div class="form-row">
            <div class="form-group">
              <label for="cors-methods">Allowed methods <span class="hint">(comma-separated)</span></label>
              <input id="cors-methods" type="text" bind:value={formCorsMethods} placeholder="GET, POST, PUT, DELETE" />
            </div>
            <div class="form-group">
              <label for="cors-max-age">Max age (s)</label>
              <input id="cors-max-age" type="number" min="0" bind:value={formCorsMaxAge} placeholder="No limit" />
            </div>
          </div>

          <h3 class="section-title">Compression</h3>
          <div class="form-group">
            <label class="checkbox-item">
              <input type="checkbox" bind:checked={formCompressionEnabled} />
              <span>Enable compression</span>
            </label>
          </div>

          <h3 class="section-title">Retry</h3>
          <div class="form-group">
            <label for="retry-attempts">Retry attempts</label>
            <input id="retry-attempts" type="number" min="0" bind:value={formRetryAttempts} placeholder="No retry" />
          </div>
        </div>
      {/if}

      <div class="form-actions">
        <button class="btn btn-cancel" onclick={closeForm}>Cancel</button>
        <button class="btn btn-primary" disabled={formSubmitting} onclick={handleSubmit}>
          {formSubmitting ? 'Saving...' : editingRoute ? 'Update' : 'Create'}
        </button>
      </div>
    </div>
  </div>
{/if}

{#if deletingRoute}
  <ConfirmDialog
    title="Delete Route"
    message="Are you sure you want to delete the route for {deletingRoute.hostname}{deletingRoute.path_prefix}? This action cannot be undone."
    onconfirm={handleDelete}
    oncancel={() => { deletingRoute = null; }}
  />
{/if}

<script lang="ts" module>
  const editIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>';
  const trashIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>';
  const chevronIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>';
</script>

<style>
  .routes-page {
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

  .error-banner {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid var(--color-red);
    border-radius: 0.5rem;
    color: var(--color-red);
    padding: 0.75rem 1rem;
    margin-bottom: 1rem;
  }

  .loading {
    color: var(--color-text-muted);
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1rem;
    padding: 3rem 0;
    color: var(--color-text-muted);
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
    padding: 0.75rem 1rem;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--color-text-muted);
    border-bottom: 1px solid var(--color-border);
  }

  td {
    padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--color-border);
    font-size: 0.875rem;
    vertical-align: middle;
  }

  tr:hover td {
    background: rgba(255, 255, 255, 0.02);
  }

  .hostname {
    font-weight: 600;
    color: var(--color-text-heading);
  }

  .mono {
    font-family: var(--mono);
    font-size: 0.8125rem;
  }

  .text-muted {
    color: var(--color-text-muted);
  }

  .small {
    font-size: 0.8125rem;
  }

  .backend-count {
    color: var(--color-text);
  }

  .tls-on {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 500;
    background: rgba(34, 197, 94, 0.1);
    color: var(--color-green);
  }

  .tls-off {
    color: var(--color-text-muted);
  }

  .waf-on {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 500;
    background: rgba(251, 146, 60, 0.1);
    color: var(--color-orange, #fb923c);
  }

  .waf-off {
    color: var(--color-text-muted);
  }

  .enabled-indicator.on {
    color: var(--color-green);
  }

  .enabled-indicator.off {
    color: var(--color-text-muted);
  }

  .actions {
    display: flex;
    gap: 0.25rem;
  }

  .btn-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 2rem;
    height: 2rem;
    border: none;
    border-radius: 0.375rem;
    background: none;
    color: var(--color-text-muted);
    transition: background-color 0.15s, color 0.15s;
  }

  .btn-icon:hover {
    background: var(--color-bg-hover);
    color: var(--color-text);
  }

  .btn-icon-danger:hover {
    background: rgba(239, 68, 68, 0.1);
    color: var(--color-red);
  }

  /* Modal / Form */
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }

  .modal {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: 0.75rem;
    padding: 1.5rem;
    width: 90%;
    max-width: 600px;
    max-height: 90vh;
    overflow-y: auto;
  }

  .modal h2 {
    margin: 0 0 1.25rem;
  }

  .form-error {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid var(--color-red);
    border-radius: 0.375rem;
    color: var(--color-red);
    padding: 0.5rem 0.75rem;
    font-size: 0.8125rem;
    margin-bottom: 1rem;
  }

  .form-group {
    margin-bottom: 1rem;
  }

  .form-group label,
  .form-group .field-label {
    display: block;
    font-size: 0.8125rem;
    font-weight: 500;
    color: var(--color-text-muted);
    margin-bottom: 0.375rem;
  }

  .required {
    color: var(--color-red);
  }

  .form-group input[type="text"],
  .form-group select {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
  }

  .form-group input[type="text"]:focus,
  .form-group select:focus {
    outline: none;
    border-color: var(--color-primary);
  }

  .form-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }

  .checkbox-list {
    display: flex;
    flex-direction: column;
    gap: 0.375rem;
    max-height: 150px;
    overflow-y: auto;
    padding: 0.5rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
  }

  .checkbox-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    cursor: pointer;
  }

  .checkbox-item input[type="checkbox"] {
    accent-color: var(--color-primary);
  }

  .form-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.75rem;
    margin-top: 1.5rem;
  }

  .btn {
    padding: 0.5rem 1rem;
    border-radius: 0.375rem;
    font-weight: 500;
    border: none;
    font-size: 0.875rem;
  }

  .btn-primary {
    background: var(--color-primary);
    color: white;
  }

  .btn-primary:hover {
    background: var(--color-primary-hover);
  }

  .btn-primary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .btn-cancel {
    background: var(--color-bg-input);
    color: var(--color-text);
  }

  .btn-cancel:hover {
    background: var(--color-bg-hover);
  }

  /* Advanced configuration */
  .advanced-toggle {
    margin: 1rem 0 0.5rem;
    border-top: 1px solid var(--color-border);
    padding-top: 1rem;
  }

  .btn-toggle {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    background: none;
    border: none;
    color: var(--color-text-muted);
    font-size: 0.8125rem;
    font-weight: 500;
    cursor: pointer;
    padding: 0.25rem 0;
  }

  .btn-toggle:hover {
    color: var(--color-text);
  }

  .toggle-arrow {
    display: inline-flex;
    transition: transform 0.2s;
  }

  .toggle-arrow.open {
    transform: rotate(90deg);
  }

  .advanced-section {
    padding: 0.5rem 0;
  }

  .section-title {
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--color-text-muted);
    margin: 1rem 0 0.75rem;
    padding-bottom: 0.375rem;
    border-bottom: 1px solid var(--color-border);
  }

  .hint {
    font-weight: 400;
    color: var(--color-text-muted);
    font-size: 0.75rem;
  }

  .form-row-3 {
    grid-template-columns: 1fr 1fr 1fr;
  }

  .form-group input[type="number"] {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
  }

  .form-group input[type="number"]:focus {
    outline: none;
    border-color: var(--color-primary);
  }

  .form-group textarea {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
    font-family: var(--mono);
    resize: vertical;
  }

  .form-group textarea:focus {
    outline: none;
    border-color: var(--color-primary);
  }
</style>
