<script lang="ts">
  import { api, type BackendResponse, type CreateBackendRequest } from '../lib/api';
  import { formStateToCreateRequest, ROUTE_DEFAULTS, type RouteFormState } from '../lib/route-form';
  import {
    parseNginxConfig,
    convertToLoricaRoutes,
    type NginxParseResult,
    type NginxDiagnostic,
    type LoricaRouteImport,
    type PathRuleImport,
    LORICA_HANDLED_DIRECTIVES,
  } from '../lib/nginx-parser';
  import { showToast } from '../lib/toast';

  interface Props {
    open: boolean;
    onclose: () => void;
    onimported: () => void;
  }

  let { open, onclose, onimported }: Props = $props();

  // Wizard state
  let step = $state(1);
  let configText = $state('');
  let parseResult: NginxParseResult | null = $state(null);
  let importRoutes: LoricaRouteImport[] = $state([]);
  let existingBackends: BackendResponse[] = $state([]);

  // Step 2: backend coherence
  interface BackendCheck {
    address: string;
    exists: boolean;
    willCreate: boolean;
    existingId?: string;
  }
  let backendChecks: BackendCheck[] = $state([]);

  // Step 2: include resolution
  interface IncludeEntry {
    line: number;
    path: string;
    content: string;
  }
  let unresolvedIncludes: IncludeEntry[] = $state([]);

  // Step 3: active preview tab
  let previewTab = $state(0);

  // Step 4: apply results
  interface ApplyResult {
    type: 'backend' | 'route';
    label: string;
    success: boolean;
    error?: string;
    routeId?: string;
  }
  let applyResults: ApplyResult[] = $state([]);
  let applying = $state(false);

  // Derived: are there blocking errors (unresolved includes)?
  let hasBlockingErrors = $derived(unresolvedIncludes.length > 0);

  // Derived: diagnostics grouped by level
  let diagnostics = $derived(parseResult?.diagnostics ?? []);
  let errors = $derived(diagnostics.filter((d) => d.level === 'error' && d.directive !== 'include'));
  let warnings = $derived(diagnostics.filter((d) => d.level === 'warning'));
  let infos = $derived(diagnostics.filter((d) => d.level === 'info'));

  // Field labels for the preview cards
  const FIELD_LABELS: Record<string, string> = {
    hostname: 'Hostname',
    path_prefix: 'Path prefix',
    hostname_aliases: 'Hostname aliases',
    force_https: 'Force HTTPS',
    redirect_to: 'Redirect to',
    redirect_hostname: 'Redirect hostname',
    backend_addresses: 'Backend addresses',
    certificate_needed: 'Certificate needed',
    proxy_headers: 'Proxy headers',
    response_headers: 'Response headers',
    proxy_headers_remove: 'Remove proxy headers',
    response_headers_remove: 'Remove response headers',
    connect_timeout_s: 'Connect timeout (s)',
    read_timeout_s: 'Read timeout (s)',
    send_timeout_s: 'Send timeout (s)',
    max_request_body_bytes: 'Max request body (bytes)',
    security_headers: 'Security headers',
    strip_path_prefix: 'Strip path prefix',
    add_path_prefix: 'Add path prefix',
    path_rewrite_pattern: 'Regex rewrite pattern',
    path_rewrite_replacement: 'Regex rewrite replacement',
    rate_limit_rps: 'Rate limit (RPS)',
    rate_limit_burst: 'Rate limit burst',
    cache_enabled: 'Cache enabled',
    cache_ttl_s: 'Cache TTL (s)',
    path_rules: 'Path rules',
    return_status: 'Return status',
  };

  // Map from Nginx directive names to display strings for the preview
  const NGINX_DIRECTIVE_MAP: Record<string, string> = {
    hostname: 'server_name',
    path_prefix: 'location',
    hostname_aliases: 'server_name (aliases)',
    force_https: 'return 301 https://',
    redirect_to: 'return 301 https://other',
    redirect_hostname: 'return 301 (www redirect)',
    backend_addresses: 'proxy_pass / upstream',
    certificate_needed: 'ssl_certificate',
    proxy_headers: 'proxy_set_header',
    response_headers: 'add_header',
    proxy_headers_remove: 'proxy_hide_header',
    connect_timeout_s: 'proxy_connect_timeout',
    read_timeout_s: 'proxy_read_timeout',
    send_timeout_s: 'proxy_send_timeout',
    max_request_body_bytes: 'client_max_body_size',
    security_headers: 'add_header (security)',
    strip_path_prefix: 'rewrite (prefix strip)',
    path_rewrite_pattern: 'rewrite (regex)',
    path_rewrite_replacement: 'rewrite (regex)',
    rate_limit_rps: 'limit_req rate=',
    rate_limit_burst: 'limit_req burst=',
    cache_enabled: 'proxy_cache',
    cache_ttl_s: 'proxy_cache_valid',
    path_rules: 'location (sub-paths)',
    return_status: 'return (status)',
  };

  function escapeRegex(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function reset() {
    step = 1;
    configText = '';
    parseResult = null;
    importRoutes = [];
    existingBackends = [];
    backendChecks = [];
    unresolvedIncludes = [];
    previewTab = 0;
    applyResults = [];
    applying = false;
  }

  function handleClose() {
    reset();
    onclose();
  }

  // Step 1 -> Step 2: parse and analyze
  async function parseAndAnalyze() {
    // Inline-replace include directives with their pasted content
    let fullText = configText;
    for (const inc of unresolvedIncludes) {
      if (inc.content.trim()) {
        const pattern = new RegExp(`^\\s*include\\s+${escapeRegex(inc.path)}\\s*;`, 'gm');
        fullText = fullText.replace(pattern, inc.content);
      }
    }

    parseResult = parseNginxConfig(fullText);
    importRoutes = convertToLoricaRoutes(parseResult);

    // Extract unresolved includes from diagnostics (deduplicate by path)
    const seenPaths = new Set<string>();
    unresolvedIncludes = parseResult.diagnostics
      .filter((d) => d.directive === 'include' && d.level === 'error')
      .filter((d) => {
        const path = d.message.replace('Unresolved include: ', '').replace('. Paste file contents to resolve.', '');
        if (seenPaths.has(path)) return false;
        seenPaths.add(path);
        return true;
      })
      .map((d) => ({
        line: d.line,
        path: d.message.replace('Unresolved include: ', '').replace('. Paste file contents to resolve.', ''),
        content: '',
      }));

    // Fetch existing backends for coherence check
    const res = await api.listBackends();
    if (res.data) {
      existingBackends = res.data.backends;
    }

    // Build backend check list from all routes (including path rule backends)
    const allAddresses = new Set<string>();
    for (const route of importRoutes) {
      for (const addr of route.backend_addresses) {
        allAddresses.add(addr);
      }
      for (const rule of route.path_rules ?? []) {
        for (const addr of rule.backend_addresses ?? []) {
          allAddresses.add(addr);
        }
      }
    }

    backendChecks = Array.from(allAddresses).map((addr) => {
      const existing = existingBackends.find((b) => b.address === addr);
      return {
        address: addr,
        exists: !!existing,
        willCreate: !existing,
        existingId: existing?.id,
      };
    });

    step = 2;
  }

  // Step 2: re-parse with includes
  async function reparseWithIncludes() {
    // Inline-replace include directives with their pasted content
    let fullText = configText;
    for (const inc of unresolvedIncludes) {
      if (inc.content.trim()) {
        const pattern = new RegExp(`^\\s*include\\s+${escapeRegex(inc.path)}\\s*;`, 'gm');
        fullText = fullText.replace(pattern, inc.content);
      }
    }

    parseResult = parseNginxConfig(fullText);
    importRoutes = convertToLoricaRoutes(parseResult);

    // Re-check includes - deduplicate by path, preserve previously entered content
    const oldContentByPath = new Map(unresolvedIncludes.map((inc) => [inc.path, inc.content]));
    const reSeenPaths = new Set<string>();
    unresolvedIncludes = parseResult.diagnostics
      .filter((d) => d.directive === 'include' && d.level === 'error')
      .filter((d) => {
        const path = d.message.replace('Unresolved include: ', '').replace('. Paste file contents to resolve.', '');
        if (reSeenPaths.has(path)) return false;
        reSeenPaths.add(path);
        return true;
      })
      .map((d) => {
        const path = d.message.replace('Unresolved include: ', '').replace('. Paste file contents to resolve.', '');
        return { line: d.line, path, content: oldContentByPath.get(path) ?? '' };
      });

    // Re-check backends (including path rule backends)
    const allAddresses = new Set<string>();
    for (const route of importRoutes) {
      for (const addr of route.backend_addresses) {
        allAddresses.add(addr);
      }
      for (const rule of route.path_rules ?? []) {
        for (const addr of rule.backend_addresses ?? []) {
          allAddresses.add(addr);
        }
      }
    }

    backendChecks = Array.from(allAddresses).map((addr) => {
      const existing = existingBackends.find((b) => b.address === addr);
      return {
        address: addr,
        exists: !!existing,
        willCreate: !existing,
        existingId: existing?.id,
      };
    });
  }

  // Nginx directive -> Lorica parameter mapping for annotations
  const LORICA_ANNOTATION: Record<string, string> = {
    server_name: 'hostname',
    proxy_pass: 'backend',
    ssl_certificate: 'certificate',
    ssl_certificate_key: 'certificate (key)',
    proxy_set_header: 'proxy_headers',
    add_header: 'response_headers',
    proxy_read_timeout: 'read_timeout_s',
    proxy_send_timeout: 'send_timeout_s',
    proxy_connect_timeout: 'connect_timeout_s',
    client_max_body_size: 'max_body_mb',
    proxy_cache_valid: 'cache_ttl_s',
    limit_req: 'rate_limit_rps',
    rewrite: 'path_rewrite',
    return: 'force_https / redirect_to',
    location: 'path_prefix',
  };

  // Build the resolved config text with include replacements shown
  type ConfigLine = { text: string; annotation: string; annotationType: 'mapped' | 'handled' | 'none'; kind: 'normal' | 'replaced' };
  let resolvedConfigLines: ConfigLine[] = $derived.by(() => {
    if (!configText.trim()) return [];
    const includeMap = new Map(unresolvedIncludes.map((inc) => [inc.path, inc.content]));
    const lines = configText.split('\n');
    const result: ConfigLine[] = [];

    function pushLine(text: string, kind: 'normal' | 'replaced' = 'normal') {
      const ann = getAnnotation(text);
      result.push({ text, annotation: ann.text, annotationType: ann.type, kind });
    }

    for (const line of lines) {
      const includeMatch = line.match(/^\s*include\s+(.+?)\s*;/);
      if (includeMatch) {
        const path = includeMatch[1];
        const content = includeMap.get(path);
        if (content?.trim()) {
          result.push({ text: `# include ${path} -> resolved:`, annotation: '', annotationType: 'none', kind: 'replaced' });
          for (const subLine of content.split('\n')) {
            pushLine(subLine);
          }
          continue;
        }
      }
      pushLine(line);
    }
    return result;
  });

  function getAnnotation(line: string): { text: string; type: 'mapped' | 'handled' | 'none' } {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed === '{' || trimmed === '}') {
      return { text: '', type: 'none' };
    }
    // Extract directive name
    const spaceIdx = trimmed.indexOf(' ');
    const tabIdx = trimmed.indexOf('\t');
    const sepIdx = spaceIdx === -1 ? tabIdx : tabIdx === -1 ? spaceIdx : Math.min(spaceIdx, tabIdx);
    const directive = sepIdx === -1 ? trimmed.replace(/;$/, '') : trimmed.substring(0, sepIdx);

    // Check if it maps to a Lorica parameter (blue)
    for (const [dir, loricaParam] of Object.entries(LORICA_ANNOTATION)) {
      if (directive === dir) {
        return { text: loricaParam, type: 'mapped' };
      }
    }
    // Check if Lorica handles it internally (gray)
    const handled = LORICA_HANDLED_DIRECTIVES[directive];
    if (handled) {
      return { text: handled, type: 'handled' };
    }
    return { text: '', type: 'none' };
  }

  function goToPreview() {
    previewTab = 0;
    step = 3;
  }

  // Format a route field value for display
  function formatFieldValue(route: LoricaRouteImport, field: string): string {
    const val = (route as Record<string, unknown>)[field];
    if (val === null || val === undefined) return '-';
    if (typeof val === 'boolean') return val ? 'Yes' : 'No';
    if (field === 'path_rules' && Array.isArray(val)) {
      return val.length > 0 ? `${val.length} rule(s)` : '-';
    }
    if (Array.isArray(val)) return val.length > 0 ? val.join(', ') : '-';
    if (typeof val === 'object' && val !== null) {
      if (val instanceof Set) return '-';
      const entries = Object.entries(val as Record<string, string>);
      return entries.length > 0 ? entries.map(([k, v]) => `${k}: ${v}`).join('; ') : '-';
    }
    return String(val);
  }

  // Get all displayable fields for a route
  function getRouteFields(route: LoricaRouteImport): { field: string; imported: boolean }[] {
    const allFields = Object.keys(FIELD_LABELS);
    return allFields.map((field) => ({
      field,
      imported: route.importedFields.has(field),
    }));
  }

  // Build a CreateRouteRequest from a LoricaRouteImport + backend ID map
  function buildCreateRequest(route: LoricaRouteImport, backendIdMap: Map<string, string>): ReturnType<typeof formStateToCreateRequest> {
    // Resolve backend_addresses to backend IDs
    const backendIds: string[] = [];
    for (const addr of route.backend_addresses) {
      const id = backendIdMap.get(addr);
      if (id) backendIds.push(id);
    }

    // Build a form state from the import
    const form: RouteFormState = {
      ...ROUTE_DEFAULTS,
      hostname: route.hostname,
      path_prefix: route.path_prefix || '/',
      backend_ids: backendIds,
      force_https: route.force_https,
      redirect_to: route.redirect_to ?? '',
      redirect_hostname: route.redirect_hostname ?? '',
      connect_timeout_s: route.connect_timeout_s,
      read_timeout_s: route.read_timeout_s,
      send_timeout_s: route.send_timeout_s,
      security_headers: route.security_headers,
      cache_enabled: route.cache_enabled,
      cache_ttl_s: route.cache_ttl_s,
      hostname_aliases: route.hostname_aliases.join(', '),
      strip_path_prefix: route.strip_path_prefix ?? '',
      add_path_prefix: route.add_path_prefix ?? '',
      path_rewrite_pattern: route.path_rewrite_pattern ?? '',
      path_rewrite_replacement: route.path_rewrite_replacement ?? '',
      max_body_mb: route.max_request_body_bytes != null ? String(route.max_request_body_bytes / (1024 * 1024)) : '',
      rate_limit_rps: route.rate_limit_rps != null ? String(route.rate_limit_rps) : '',
      rate_limit_burst: route.rate_limit_burst != null ? String(route.rate_limit_burst) : '',
      proxy_headers: Object.entries(route.proxy_headers).map(([k, v]) => `${k}=${v}`).join('\n'),
      proxy_headers_remove: route.proxy_headers_remove.join(', '),
      response_headers: Object.entries(route.response_headers).map(([k, v]) => `${k}=${v}`).join('\n'),
      response_headers_remove: route.response_headers_remove.join(', '),
      path_rules: (route.path_rules ?? []).map((pr: PathRuleImport) => ({
        path: pr.path,
        match_type: pr.match_type ?? 'prefix',
        backend_ids: (pr.backend_addresses ?? []).map(a => backendIdMap.get(a)).filter((id): id is string => !!id),
        cache_enabled: pr.cache_enabled ?? null,
        cache_ttl_s: pr.cache_ttl_s ?? null,
        response_headers: pr.response_headers
          ? Object.entries(pr.response_headers).map(([k, v]) => `${k}=${v}`).join('\n')
          : '',
        response_headers_remove: '',
        rate_limit_rps: pr.rate_limit_rps != null ? String(pr.rate_limit_rps) : '',
        rate_limit_burst: pr.rate_limit_burst != null ? String(pr.rate_limit_burst) : '',
        redirect_to: pr.redirect_to ?? '',
        return_status: pr.return_status != null ? String(pr.return_status) : '',
      })),
      return_status: route.return_status != null ? String(route.return_status) : '',
    };

    return formStateToCreateRequest(form);
  }

  // Builtin security header presets for comparison
  const BUILTIN_PRESETS: Record<string, Record<string, string>> = {
    strict: {
      'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': "default-src 'self'",
      'Permissions-Policy': 'geolocation=(), camera=(), microphone=()',
      'X-XSS-Protection': '1; mode=block',
    },
    moderate: {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'SAMEORIGIN',
      'X-XSS-Protection': '1; mode=block',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
    },
  };

  function headersMatch(a: Record<string, string>, b: Record<string, string>): boolean {
    // Normalize keys to lowercase for case-insensitive comparison
    const normA = Object.fromEntries(Object.entries(a).map(([k, v]) => [k.toLowerCase(), v]));
    const normB = Object.fromEntries(Object.entries(b).map(([k, v]) => [k.toLowerCase(), v]));
    const keysA = Object.keys(normA).sort();
    const keysB = Object.keys(normB).sort();
    if (keysA.length !== keysB.length) return false;
    return keysA.every((k, i) => k === keysB[i] && normA[k] === normB[k]);
  }

  async function resolveSecurityPresets() {
    // Collect routes that need preset resolution
    const routesWithAuto = importRoutes.filter(r => r.security_headers === 'auto' && r._securityHeaders);
    if (routesWithAuto.length === 0) return;

    // Fetch existing custom presets
    const settingsRes = await api.getSettings();
    const customPresets: Record<string, Record<string, string>> = {};
    if (settingsRes.data?.custom_security_presets) {
      for (const p of settingsRes.data.custom_security_presets) {
        customPresets[p.name] = p.headers;
      }
    }

    // All known presets: builtins + existing customs
    const allPresets = { ...BUILTIN_PRESETS, ...customPresets };

    // New presets to create
    const newPresets: { name: string; headers: Record<string, string> }[] = [];

    for (const route of routesWithAuto) {
      const imported = route._securityHeaders!;

      // Try to match an existing preset
      let matched: string | null = null;
      for (const [name, headers] of Object.entries(allPresets)) {
        if (headersMatch(imported, headers)) {
          matched = name;
          break;
        }
      }

      if (matched) {
        route.security_headers = matched;
      } else {
        // Create a new preset named after the hostname
        const presetName = route.hostname || 'imported';
        // Avoid duplicates if multiple routes have the same unmatched headers
        if (!allPresets[presetName]) {
          newPresets.push({ name: presetName, headers: imported });
          allPresets[presetName] = imported;
        }
        route.security_headers = presetName;
      }
    }

    // Save new presets via settings API
    if (newPresets.length > 0) {
      const existingList = settingsRes.data?.custom_security_presets ?? [];
      const merged = [...existingList, ...newPresets];
      const res = await api.updateSettings({ custom_security_presets: merged });
      if (res.error) {
        applyResults = [...applyResults, {
          type: 'backend' as const,
          label: 'Security presets',
          success: false,
          error: res.error.message,
        }];
      } else {
        for (const p of newPresets) {
          applyResults = [...applyResults, {
            type: 'backend' as const,
            label: `Security preset "${p.name}"`,
            success: true,
          }];
        }
      }
    }
  }

  // Step 4: apply
  async function applyImport() {
    applying = true;
    applyResults = [];

    // Build a map of address -> backend ID (existing + newly created)
    const backendIdMap = new Map<string, string>();

    // Add existing backends
    for (const check of backendChecks) {
      if (check.exists && check.existingId) {
        backendIdMap.set(check.address, check.existingId);
      }
    }

    // Create new backends
    for (const check of backendChecks) {
      if (check.willCreate && !check.exists) {
        const body: CreateBackendRequest = {
          address: check.address,
          name: check.address,
        };
        const res = await api.createBackend(body);
        if (res.error) {
          applyResults = [...applyResults, {
            type: 'backend',
            label: check.address,
            success: false,
            error: res.error.message,
          }];
        } else if (res.data) {
          backendIdMap.set(check.address, res.data.id);
          applyResults = [...applyResults, {
            type: 'backend',
            label: check.address,
            success: true,
          }];
        }
      }
    }

    // Resolve security header presets: match imported headers against existing presets,
    // create custom presets for unmatched configurations
    await resolveSecurityPresets();

    // Create routes
    for (const route of importRoutes) {
      const req = buildCreateRequest(route, backendIdMap);
      const label = `${route.hostname}${route.path_prefix}`;
      const res = await api.createRoute(req);
      if (res.error) {
        applyResults = [...applyResults, {
          type: 'route',
          label,
          success: false,
          error: res.error.message,
        }];
      } else if (res.data) {
        applyResults = [...applyResults, {
          type: 'route',
          label,
          success: true,
          routeId: res.data.id,
        }];
      }
    }

    applying = false;
    step = 4;
  }

  function handleFinish() {
    const anySuccess = applyResults.some((r) => r.success);
    if (anySuccess) {
      onimported();
    }
    handleClose();
  }
</script>

{#if open}
  <div class="wizard-overlay" role="dialog" aria-modal="true" aria-label="Nginx Import Wizard">
    <div class="wizard-container">
      <!-- Header -->
      <div class="wizard-header">
        <h2>Import from Nginx</h2>
        <button class="wizard-close" onclick={handleClose} aria-label="Close">
          {@html closeIcon}
        </button>
      </div>

      <!-- Stepper -->
      <div class="stepper">
        {#each stepLabels as label, i}
          {@const stepNum = i + 1}
          <div class="stepper-item" class:active={step === stepNum} class:completed={step > stepNum}>
            <div class="stepper-circle">
              {#if step > stepNum}
                {@html checkIcon}
              {:else}
                {stepNum}
              {/if}
            </div>
            <span class="stepper-label">{label}</span>
          </div>
          {#if i < stepLabels.length - 1}
            <div class="stepper-line" class:completed={step > stepNum}></div>
          {/if}
        {/each}
      </div>

      <!-- Step content -->
      <div class="wizard-body">
        {#if step === 1}
          <!-- STEP 1: Paste -->
          <div class="step-content">
            <p class="step-hint">Paste your Nginx <code>server {'{}'}</code> and <code>upstream {'{}'}</code> blocks below.</p>
            <textarea
              class="config-textarea"
              bind:value={configText}
              placeholder="server {'\n'}    listen 80;{'\n'}    server_name example.com;{'\n'}    location / {'{'}  {'\n'}        proxy_pass http://127.0.0.1:8080;{'\n'}    {'}'}{'\n'}{'}'}"
              rows="22"
              spellcheck="false"
            ></textarea>
            <div class="step-actions">
              <button class="btn btn-ghost" onclick={handleClose}>Cancel</button>
              <button
                class="btn btn-primary"
                disabled={!configText.trim()}
                onclick={parseAndAnalyze}
              >Parse & Analyze</button>
            </div>
          </div>

        {:else if step === 2}
          <!-- STEP 2: Analysis -->
          <div class="step-content">
            <h3>Analysis results</h3>

            <!-- Unresolved includes -->
            {#if unresolvedIncludes.length > 0}
              <div class="section">
                <h4>Unresolved includes</h4>
                <p class="step-hint">Paste the content of each included file to resolve them, then click "Re-parse".</p>
                {#each unresolvedIncludes as inc, i}
                  <div class="include-entry">
                    <label class="include-label">
                      <span class="badge badge-error">include</span>
                      <code>{inc.path}</code> (line {inc.line})
                    </label>
                    <textarea
                      class="include-textarea"
                      bind:value={unresolvedIncludes[i].content}
                      placeholder="Paste file contents here..."
                      rows="6"
                      spellcheck="false"
                    ></textarea>
                  </div>
                {/each}
                <button class="btn btn-secondary" onclick={reparseWithIncludes}>Re-parse</button>
              </div>
            {/if}

            <!-- Resolved config view -->
            {#if resolvedConfigLines.length > 0}
              <div class="section">
                <h4>Resolved configuration</h4>
                <div class="resolved-config">
                  {#each resolvedConfigLines as line, i}
                    <div class="resolved-line" class:resolved-replaced={line.kind === 'replaced'}>
                      <span class="resolved-lineno">{i + 1}</span>
                      <span class="resolved-text">{line.text}</span>
                      {#if line.annotation}
                        <span class="resolved-annotation" class:annotation-mapped={line.annotationType === 'mapped'} class:annotation-handled={line.annotationType === 'handled'}>{line.annotation}</span>
                      {/if}
                    </div>
                  {/each}
                </div>
              </div>
            {/if}

            <!-- Diagnostics -->
            {#if diagnostics.length > 0}
              <div class="section">
                <h4>Diagnostics</h4>
                <div class="diagnostics-list">
                  {#each errors as d}
                    <div class="diagnostic diagnostic-error">
                      <span class="diag-level">ERROR</span>
                      <span class="diag-line">L{d.line}</span>
                      <span class="diag-msg">{d.message}</span>
                    </div>
                  {/each}
                  {#each warnings as d}
                    <div class="diagnostic diagnostic-warning">
                      <span class="diag-level">WARN</span>
                      <span class="diag-line">L{d.line}</span>
                      <span class="diag-msg">{d.message}</span>
                    </div>
                  {/each}
                  {#each infos as d}
                    <div class="diagnostic diagnostic-info">
                      <span class="diag-level">INFO</span>
                      <span class="diag-line">L{d.line}</span>
                      <span class="diag-msg">{d.message}</span>
                    </div>
                  {/each}
                </div>
              </div>
            {/if}

            <!-- Summary -->
            <div class="section">
              <h4>Parsed</h4>
              <div class="summary-row">
                <span>{parseResult?.servers.length ?? 0} server block(s)</span>
                <span>{parseResult?.upstreams.length ?? 0} upstream block(s)</span>
                <span>{importRoutes.length} route(s) to import</span>
              </div>
              {#if importRoutes.length === 0 && errors.length === 0}
                <p class="step-hint" style="margin-top: 0.75rem;">No routes were detected. The parser expects <code>server</code> blocks containing <code>server_name</code> and <code>proxy_pass</code> directives.</p>
              {/if}
            </div>

            <!-- Backend coherence -->
            {#if backendChecks.length > 0}
              <div class="section">
                <h4>Backends</h4>
                <div class="backend-checks">
                  {#each backendChecks as check, i}
                    <div class="backend-check-row">
                      <code class="backend-addr">{check.address}</code>
                      {#if check.exists}
                        <span class="badge badge-success">Exists in Lorica</span>
                      {:else}
                        <label class="backend-create-label">
                          <input type="checkbox" bind:checked={backendChecks[i].willCreate} />
                          <span class="badge badge-create">Will be created</span>
                        </label>
                      {/if}
                    </div>
                  {/each}
                </div>
              </div>
            {/if}

            <div class="step-actions">
              <button class="btn btn-ghost" onclick={() => { step = 1; }}>Back</button>
              <button
                class="btn btn-primary"
                disabled={hasBlockingErrors || importRoutes.length === 0}
                onclick={goToPreview}
              >Continue</button>
            </div>
          </div>

        {:else if step === 3}
          <!-- STEP 3: Preview -->
          <div class="step-content">
            <h3>Route preview</h3>

            {#if importRoutes.length > 1}
              <div class="preview-tabs">
                {#each importRoutes as route, i}
                  <button
                    class="preview-tab"
                    class:active={previewTab === i}
                    onclick={() => { previewTab = i; }}
                  >
                    {route.hostname || '(no host)'}{route.path_prefix}
                  </button>
                {/each}
              </div>
            {/if}

            {#if importRoutes[previewTab]}
              {@const route = importRoutes[previewTab]}
              <div class="preview-card">
                {#each getRouteFields(route) as { field, imported }}
                  {@const value = formatFieldValue(route, field)}
                  {#if imported || value !== '-'}
                    <div class="preview-row" class:imported class:dimmed={!imported}>
                      <div class="preview-nginx">
                        <code>{NGINX_DIRECTIVE_MAP[field] ?? field}</code>
                      </div>
                      <div class="preview-lorica">
                        <span class="preview-field-name">{FIELD_LABELS[field] ?? field}</span>
                        <span class="preview-field-value">{value}</span>
                        {#if imported}
                          <span class="badge badge-imported">imported</span>
                        {/if}
                      </div>
                    </div>
                  {/if}
                {/each}
              </div>
              {#if route.path_rules && route.path_rules.length > 0}
                <div class="preview-path-rules">
                  <h5>Path Rules ({route.path_rules.length})</h5>
                  {#each route.path_rules as rule}
                    <div class="path-rule-preview">
                      <code>{rule.match_type === 'exact' ? '= ' : ''}{rule.path}</code>
                      {#if rule.backend_addresses}<span class="rule-override">backends: {rule.backend_addresses.join(', ')}</span>{/if}
                      {#if rule.cache_enabled}<span class="rule-override">cache: {rule.cache_ttl_s}s</span>{/if}
                      {#if rule.response_headers}<span class="rule-override">headers: {Object.entries(rule.response_headers).map(([k, v]) => `${k}: ${v}`).join('; ')}</span>{/if}
                      {#if rule.return_status}<span class="rule-override">return {rule.return_status}</span>{/if}
                      {#if rule.redirect_to}<span class="rule-override">redirect: {rule.redirect_to}</span>{/if}
                      {#if rule.rate_limit_rps}<span class="rule-override">rate limit: {rule.rate_limit_rps} rps</span>{/if}
                    </div>
                  {/each}
                </div>
              {/if}
              <p class="step-hint">Fields are read-only here. You can edit them in the Route Drawer after import.</p>
            {/if}

            <div class="step-actions">
              <button class="btn btn-ghost" onclick={() => { step = 2; }}>Back</button>
              <button class="btn btn-primary" onclick={applyImport} disabled={applying}>
                {applying ? 'Applying...' : 'Apply import'}
              </button>
            </div>
          </div>

        {:else if step === 4}
          <!-- STEP 4: Results -->
          <div class="step-content">
            <h3>Import results</h3>
            <div class="results-list">
              {#each applyResults as result}
                <div class="result-row" class:success={result.success} class:failure={!result.success}>
                  <span class="result-icon">
                    {#if result.success}
                      {@html checkIcon}
                    {:else}
                      {@html xIcon}
                    {/if}
                  </span>
                  <span class="result-type">{result.type === 'backend' ? 'Backend' : 'Route'}</span>
                  <span class="result-label">{result.label}</span>
                  {#if result.error}
                    <span class="result-error">{result.error}</span>
                  {/if}
                </div>
              {/each}
            </div>

            {#if importRoutes.some((r) => r.certificate_needed)}
              <div class="cert-notice">
                <strong>TLS certificates needed</strong>
                <p>The imported route(s) had SSL certificates configured in Nginx. Upload or provision the certificates in the Certificates page, then assign them to the imported route(s) in the Route Drawer to enable HTTPS.</p>
              </div>
            {/if}

            <div class="step-actions">
              <button class="btn btn-primary" onclick={handleFinish}>Close</button>
            </div>
          </div>
        {/if}
      </div>
    </div>
  </div>
{/if}

<script lang="ts" module>
  const stepLabels = ['Paste', 'Analysis', 'Preview', 'Apply'];

  const closeIcon = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
  const checkIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
  const xIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
</script>

<style>
  .wizard-overlay {
    position: fixed;
    inset: 0;
    z-index: 200;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: var(--space-4);
  }

  .wizard-container {
    background: var(--color-bg-card);
    border-radius: var(--radius-xl);
    box-shadow: 0 25px 50px rgba(0, 0, 0, 0.25);
    max-width: 1200px;
    width: 100%;
    max-height: 90vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .wizard-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--space-5) var(--space-6);
    border-bottom: 1px solid var(--color-border);
  }

  .wizard-header h2 {
    margin: 0;
    font-size: var(--text-lg);
    color: var(--color-text-heading);
  }

  .wizard-close {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 2rem;
    height: 2rem;
    border: none;
    border-radius: var(--radius-md);
    background: none;
    color: var(--color-text-muted);
    cursor: pointer;
  }

  .wizard-close:hover {
    background: var(--color-bg-hover);
    color: var(--color-text);
  }

  /* Stepper */
  .stepper {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: var(--space-5) var(--space-6);
    gap: 0;
    border-bottom: 1px solid var(--color-border);
  }

  .stepper-item {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-1);
  }

  .stepper-circle {
    width: 2rem;
    height: 2rem;
    border-radius: var(--radius-full);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: var(--text-sm);
    font-weight: 600;
    border: 2px solid var(--color-border);
    color: var(--color-text-muted);
    background: var(--color-bg-card);
    transition: all 0.2s;
  }

  .stepper-item.active .stepper-circle {
    border-color: var(--color-primary);
    background: var(--color-primary);
    color: white;
  }

  .stepper-item.completed .stepper-circle {
    border-color: var(--color-green);
    background: var(--color-green);
    color: white;
  }

  .stepper-label {
    font-size: var(--text-xs);
    color: var(--color-text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .stepper-item.active .stepper-label {
    color: var(--color-primary);
    font-weight: 600;
  }

  .stepper-item.completed .stepper-label {
    color: var(--color-green);
  }

  .stepper-line {
    flex: 1;
    height: 2px;
    background: var(--color-border);
    margin: 0 var(--space-2);
    margin-bottom: 1.25rem;
    max-width: 6rem;
    transition: background 0.2s;
  }

  .stepper-line.completed {
    background: var(--color-green);
  }

  /* Body */
  .wizard-body {
    flex: 1;
    overflow-y: auto;
    padding: var(--space-6);
  }

  .step-content {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .step-content h3 {
    margin: 0;
    font-size: var(--text-md);
    color: var(--color-text-heading);
  }

  .step-hint {
    color: var(--color-text-muted);
    font-size: var(--text-sm);
    margin: 0;
  }

  .step-hint code {
    background: var(--color-bg-input);
    padding: 0.125rem 0.375rem;
    border-radius: var(--radius-sm);
    font-family: var(--mono);
    font-size: var(--text-sm);
  }

  .step-actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--space-3);
    padding-top: var(--space-4);
    border-top: 1px solid var(--color-border);
  }

  /* Config textarea */
  .config-textarea {
    width: 100%;
    min-height: 22rem;
    resize: vertical;
    font-family: var(--mono);
    font-size: var(--text-sm);
    line-height: 1.6;
    padding: var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg-input);
    color: var(--color-text);
    tab-size: 4;
  }

  .config-textarea:focus {
    outline: none;
    border-color: var(--color-primary);
    box-shadow: 0 0 0 3px var(--color-primary-subtle);
  }

  /* Buttons */
  .btn {
    padding: 0.5rem 1rem;
    border-radius: var(--radius-md);
    font-weight: 500;
    border: none;
    font-size: var(--text-md);
    cursor: pointer;
    transition: background 0.15s, color 0.15s;
  }

  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .btn-primary {
    background: var(--color-primary);
    color: white;
  }

  .btn-primary:hover:not(:disabled) {
    background: var(--color-primary-hover);
  }

  .btn-ghost {
    background: none;
    color: var(--color-text-muted);
    border: 1px solid var(--color-border);
  }

  .btn-ghost:hover {
    background: var(--color-bg-hover);
    color: var(--color-text);
  }

  .btn-secondary {
    background: var(--color-bg-hover);
    color: var(--color-text);
    border: 1px solid var(--color-border);
  }

  .btn-secondary:hover {
    background: var(--color-border);
  }

  /* Sections */
  .section {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .section h4 {
    margin: 0;
    font-size: var(--text-base);
    color: var(--color-text-heading);
  }

  /* Diagnostics */
  .diagnostics-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .diagnostic {
    display: flex;
    align-items: baseline;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
  }

  .diagnostic-error {
    background: var(--color-red-subtle);
    color: var(--color-red);
  }

  .diagnostic-warning {
    background: var(--color-orange-subtle);
    color: var(--color-orange);
  }

  .diagnostic-info {
    background: var(--color-primary-subtle);
    color: var(--color-text-muted);
  }

  .diag-level {
    font-weight: 700;
    font-size: var(--text-xs);
    text-transform: uppercase;
    min-width: 3rem;
  }

  .diag-line {
    font-family: var(--mono);
    font-size: var(--text-xs);
    opacity: 0.7;
    min-width: 2.5rem;
  }

  .diag-msg {
    flex: 1;
  }

  /* Summary */
  .summary-row {
    display: flex;
    gap: var(--space-6);
    font-size: var(--text-sm);
    color: var(--color-text);
  }

  /* Badges */
  .badge {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    border-radius: var(--radius-full);
    font-size: var(--text-xs);
    font-weight: 600;
  }

  .badge-success {
    background: var(--color-green-subtle);
    color: var(--color-green);
  }

  .badge-error {
    background: var(--color-red-subtle);
    color: var(--color-red);
  }

  .badge-create {
    background: var(--color-red-subtle);
    color: var(--color-red);
  }

  .badge-imported {
    background: var(--color-primary-subtle);
    color: var(--color-primary);
  }

  /* Backend checks */
  .backend-checks {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .backend-check-row {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-2) var(--space-3);
    background: var(--color-bg-input);
    border-radius: var(--radius-md);
  }

  .backend-addr {
    font-family: var(--mono);
    font-size: var(--text-sm);
    flex: 1;
  }

  .backend-create-label {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    cursor: pointer;
  }

  .backend-create-label input[type="checkbox"] {
    accent-color: var(--color-primary);
  }

  /* Includes */
  .include-entry {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .include-label {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-size: var(--text-sm);
  }

  .include-label code {
    font-family: var(--mono);
    font-size: var(--text-sm);
    color: var(--color-text);
  }

  .include-textarea {
    width: 100%;
    resize: vertical;
    font-family: var(--mono);
    font-size: var(--text-xs);
    line-height: 1.5;
    padding: var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg-input);
    color: var(--color-text);
  }

  .include-textarea:focus {
    outline: none;
    border-color: var(--color-primary);
    box-shadow: 0 0 0 3px var(--color-primary-subtle);
  }

  /* Resolved config */
  .resolved-config {
    max-height: 24rem;
    overflow-y: auto;
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg-input);
    font-family: var(--mono);
    font-size: var(--text-xs);
    line-height: 1.6;
  }

  .resolved-line {
    display: flex;
    align-items: baseline;
    padding: 0 var(--space-2);
    min-height: 1.5em;
  }

  .resolved-line:hover {
    background: var(--color-bg-hover);
  }

  .resolved-lineno {
    min-width: 2.5rem;
    text-align: right;
    padding-right: var(--space-2);
    color: var(--color-text-muted);
    opacity: 0.5;
    user-select: none;
  }

  .resolved-text {
    flex: 1;
    white-space: pre;
  }

  .resolved-annotation {
    margin-left: auto;
    padding-left: var(--space-4);
    font-weight: 600;
    font-size: var(--text-xs);
    white-space: nowrap;
    opacity: 0.9;
    color: var(--color-text-muted);
  }

  .annotation-mapped {
    color: var(--color-primary);
  }

  .annotation-handled {
    color: var(--color-text-muted);
    font-weight: 400;
    font-style: italic;
  }

  .resolved-replaced .resolved-text {
    color: var(--color-green);
    font-style: italic;
  }


  /* Preview tabs */
  .preview-tabs {
    display: flex;
    gap: var(--space-1);
    border-bottom: 1px solid var(--color-border);
    overflow-x: auto;
  }

  .preview-tab {
    padding: var(--space-2) var(--space-3);
    border: none;
    background: none;
    color: var(--color-text-muted);
    font-size: var(--text-sm);
    font-family: var(--mono);
    cursor: pointer;
    border-bottom: 2px solid transparent;
    white-space: nowrap;
  }

  .preview-tab.active {
    color: var(--color-primary);
    border-bottom-color: var(--color-primary);
  }

  .preview-tab:hover:not(.active) {
    color: var(--color-text);
  }

  /* Preview card */
  .preview-card {
    border: 1px solid var(--color-border);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }

  .preview-row {
    display: grid;
    grid-template-columns: 1fr 2fr;
    border-bottom: 1px solid var(--color-border);
  }

  .preview-row:last-child {
    border-bottom: none;
  }

  .preview-row.imported {
    border-left: 3px solid var(--color-primary);
  }

  .preview-row.dimmed {
    opacity: 0.5;
  }

  .preview-nginx {
    padding: var(--space-2) var(--space-3);
    background: var(--color-bg-input);
    font-family: var(--mono);
    font-size: var(--text-xs);
    color: var(--color-text-muted);
    display: flex;
    align-items: center;
  }

  .preview-lorica {
    padding: var(--space-2) var(--space-3);
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-size: var(--text-sm);
  }

  .preview-field-name {
    font-weight: 600;
    color: var(--color-text-heading);
    min-width: 10rem;
  }

  .preview-field-value {
    color: var(--color-text);
    font-family: var(--mono);
    font-size: var(--text-xs);
    word-break: break-all;
  }

  /* Path rules preview */
  .preview-path-rules {
    margin-top: var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-lg);
    padding: var(--space-3);
  }

  .preview-path-rules h5 {
    margin: 0 0 var(--space-2) 0;
    font-size: var(--text-sm);
    color: var(--color-text-heading);
  }

  .path-rule-preview {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-1) var(--space-2);
    font-size: var(--text-sm);
    border-bottom: 1px solid var(--color-border);
  }

  .path-rule-preview:last-child {
    border-bottom: none;
  }

  .path-rule-preview code {
    font-family: var(--mono);
    font-size: var(--text-xs);
    background: var(--color-bg-input);
    padding: 0.125rem 0.375rem;
    border-radius: var(--radius-sm);
    min-width: 6rem;
  }

  .rule-override {
    font-size: var(--text-xs);
    color: var(--color-text-muted);
    font-family: var(--mono);
  }

  /* Results */
  .results-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .result-row {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-3);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
  }

  .result-row.success {
    background: var(--color-green-subtle);
  }

  .result-row.failure {
    background: var(--color-red-subtle);
  }

  .result-icon {
    display: flex;
    align-items: center;
  }

  .result-row.success .result-icon {
    color: var(--color-green);
  }

  .result-row.failure .result-icon {
    color: var(--color-red);
  }

  .result-type {
    font-weight: 600;
    min-width: 4rem;
    color: var(--color-text-heading);
  }

  .result-label {
    flex: 1;
    font-family: var(--mono);
    color: var(--color-text);
  }

  .result-error {
    color: var(--color-red);
    font-size: var(--text-xs);
  }

  .cert-notice {
    padding: var(--space-3) var(--space-4);
    border-radius: var(--radius-md);
    background: var(--color-primary-subtle);
    border: 1px solid var(--color-primary);
    font-size: var(--text-sm);
    margin-top: var(--space-3);
  }

  .cert-notice strong {
    color: var(--color-primary);
  }

  .cert-notice p {
    margin: var(--space-1) 0 0;
    color: var(--color-text-muted);
  }
</style>
