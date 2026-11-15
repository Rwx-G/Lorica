<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    type BackendResponse,
    type CreateBackendRequest,
    type HealthCheck,
    type HealthCheckPayload,
    type MatchAnchor,
    type TcpCheckTemplateName,
    type UpdateBackendRequest,
  } from '../lib/api';
  import {
    EXPECT_MAX_ALTERNATIVES,
    EXPECT_MAX_BYTES,
    PROBE_TIMEOUT_MS_DEFAULT,
    PROBE_TIMEOUT_MS_MAX,
    PROBE_TIMEOUT_MS_MIN,
    SEND_MAX_BYTES,
    TCP_CHECK_TEMPLATES,
    type CheckTemplate,
  } from '../lib/health-check-templates.generated';
  import StatusBadge from '../components/StatusBadge.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import AutomationBadge from '../components/AutomationBadge.svelte';
  import { managedDeleteHint, managedEditHint } from '../lib/managed-by';
  import { showToast } from '../lib/toast';
  import { canWrite } from '../lib/auth';

  let backends: BackendResponse[] = $state([]);
  let error = $state('');
  let loading = $state(true);

  let showForm = $state(false);
  let editingBackend: BackendResponse | null = $state(null);
  let formAddress = $state('');
  let formName = $state('');
  let formGroupName = $state('');
  let formWeight = $state(100);
  let formHealthCheckEnabled = $state(true);
  // `null` on a create until the operator types one: the request then
  // omits the interval and the server stores its
  // `default_health_check_interval_s`, as it does for every other field
  // the form leaves empty.
  let formHealthCheckInterval: number | null = $state(null);
  let formHealthCheckKind: HealthCheck['kind'] = $state('tcp_connect');
  let formHealthCheckPath = $state('');

  // A template or a custom send/expect check (Story 12.7). The limits
  // below come from the generated module, so the form refuses what the
  // server would; the server stays the authority and its refusal is
  // shown as it comes.
  type PayloadEncoding = 'text' | 'hex';
  interface ExpectDraft { match: MatchAnchor; encoding: PayloadEncoding; value: string }
  let formTemplate: TcpCheckTemplateName = $state(TCP_CHECK_TEMPLATES[0].name);
  // `null` leaves the probe timeout to the server default.
  let formProbeTimeout: number | null = $state(null);
  let formSendEncoding: PayloadEncoding = $state('text');
  let formSend = $state('');
  let formExpect: ExpectDraft[] = $state([newExpectDraft()]);

  function newExpectDraft(): ExpectDraft {
    return { match: 'prefix', encoding: 'text', value: '' };
  }

  let selectedTemplate: CheckTemplate | undefined = $derived(
    TCP_CHECK_TEMPLATES.find((template) => template.name === formTemplate),
  );
  let formTlsUpstream = $state(false);
  let formTlsSkipVerify = $state(false);
  let formTlsSni = $state('');
  let formH2Upstream = $state(false);
  let formError = $state('');
  let formSubmitting = $state(false);

  let addressError = $state('');

  let deletingBackend: BackendResponse | null = $state(null);

  // Search and sort state
  let searchQuery = $state('');
  let sortColumn = $state('');
  let sortDirection: 'asc' | 'desc' = $state('asc');

  function toggleSort(col: string) {
    if (sortColumn === col) {
      sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
    } else {
      sortColumn = col;
      sortDirection = 'asc';
    }
  }

  let filteredBackends: BackendResponse[] = $derived.by(() => {
    let result = backends;
    if (searchQuery.trim()) {
      const q = searchQuery.trim().toLowerCase();
      result = result.filter((b) =>
        (b.name ?? '').toLowerCase().includes(q) ||
        (b.group_name ?? '').toLowerCase().includes(q) ||
        b.address.toLowerCase().includes(q)
      );
    }
    if (sortColumn) {
      result = [...result].sort((a, b) => {
        let va: string | number = '';
        let vb: string | number = '';
        switch (sortColumn) {
          case 'name': va = (a.name ?? '').toLowerCase(); vb = (b.name ?? '').toLowerCase(); break;
          case 'group': va = (a.group_name ?? '').toLowerCase(); vb = (b.group_name ?? '').toLowerCase(); break;
          case 'address': va = a.address.toLowerCase(); vb = b.address.toLowerCase(); break;
          case 'health': va = a.health_status; vb = b.health_status; break;
        }
        if (va < vb) return sortDirection === 'asc' ? -1 : 1;
        if (va > vb) return sortDirection === 'asc' ? 1 : -1;
        return 0;
      });
    }
    return result;
  });

  const ADDRESS_PATTERN = /^[a-zA-Z0-9._-]+:\d{1,5}$/;

  function validateAddress(value: string): string {
    if (!value.trim()) return 'Address is required (e.g. 10.0.0.1:8080)';
    if (!ADDRESS_PATTERN.test(value.trim())) return 'Address must be in host:port format';
    const port = parseInt(value.split(':').pop()!, 10);
    if (port < 1 || port > 65535) return 'Port must be between 1 and 65535';
    return '';
  }

  function validate(): string {
    const addrErr = validateAddress(formAddress);
    if (addrErr) return addrErr;
    if (formWeight < 1 || formWeight > 1000) return 'Weight must be between 1 and 1000';
    if (formHealthCheckInterval != null && (formHealthCheckInterval < 5 || formHealthCheckInterval > 3600)) return 'Health check interval must be between 5 and 3600 seconds';
    if (formHealthCheckKind === 'http' && !formHealthCheckPath.trim()) return 'An HTTP health check needs a path (e.g. /healthz)';
    if (formHealthCheckKind === 'tcp_template' || formHealthCheckKind === 'tcp_send_expect') {
      return validateExchange();
    }
    return '';
  }

  /// The client-side mirror of the server's limits on a template or a
  /// custom check (`HealthCheck::validate` and the TLS refusal).
  function validateExchange(): string {
    if (formTlsUpstream) return 'A template or a send/expect check speaks plaintext TCP: switch TLS upstream off, or use a TCP connect check';
    if (formProbeTimeout != null && (formProbeTimeout < PROBE_TIMEOUT_MS_MIN || formProbeTimeout > PROBE_TIMEOUT_MS_MAX)) {
      return `Probe timeout must be between ${PROBE_TIMEOUT_MS_MIN} and ${PROBE_TIMEOUT_MS_MAX} ms`;
    }
    if (formHealthCheckKind === 'tcp_template') return '';
    const sendError = payloadError('Send', formSendEncoding, formSend, SEND_MAX_BYTES, true);
    if (sendError) return sendError;
    if (formExpect.length === 0) return 'A send/expect check needs at least one answer; a check that expects nothing is a TCP connect';
    if (formExpect.length > EXPECT_MAX_ALTERNATIVES) return `At most ${EXPECT_MAX_ALTERNATIVES} answers`;
    for (const [index, draft] of formExpect.entries()) {
      const error = payloadError(`Answer ${index + 1}`, draft.encoding, draft.value, EXPECT_MAX_BYTES, false);
      if (error) return error;
    }
    return '';
  }

  /// Why the payload typed as `value` in `encoding` is refused, or ''.
  /// An optional payload left empty is absent, never an empty one.
  function payloadError(label: string, encoding: PayloadEncoding, value: string, maxBytes: number, optional: boolean): string {
    if (value === '') return optional ? '' : `${label} is empty: an empty answer matches anything`;
    const bytes = payloadLength(encoding, value);
    if (bytes === null) {
      return encoding === 'hex'
        ? `${label} must be an even number of hexadecimal digits`
        : `${label} has an unknown escape: use \\r, \\n, \\t or \\\\, or switch to hex`;
    }
    if (bytes > maxBytes) return `${label} is ${bytes} bytes, above the limit of ${maxBytes}`;
    return '';
  }

  /// The decoded size of a payload, or `null` when it does not decode.
  function payloadLength(encoding: PayloadEncoding, value: string): number | null {
    if (encoding === 'hex') return /^([0-9a-fA-F]{2})+$/.test(value) ? value.length / 2 : null;
    const text = unescapeText(value);
    return text === null ? null : new TextEncoder().encode(text).length;
  }

  /// A text payload as the form shows it: the four escapes a text field
  /// cannot hold typed (`\r`, `\n`, `\t`) or would read ambiguously
  /// (`\\`). `unescapeText` is its inverse, so a stored payload loaded
  /// into the form saves back unchanged.
  function escapeText(raw: string): string {
    return raw.replace(/\\/g, '\\\\').replace(/\r/g, '\\r').replace(/\n/g, '\\n').replace(/\t/g, '\\t');
  }

  function unescapeText(typed: string): string | null {
    let out = '';
    for (let i = 0; i < typed.length; i++) {
      const c = typed[i];
      if (c !== '\\') { out += c; continue; }
      i += 1;
      switch (typed[i]) {
        case 'r': out += '\r'; break;
        case 'n': out += '\n'; break;
        case 't': out += '\t'; break;
        case '\\': out += '\\'; break;
        default: return null;
      }
    }
    return out;
  }

  function payloadOf(encoding: PayloadEncoding, value: string): HealthCheckPayload {
    return encoding === 'hex' ? { hex: value } : { text: unescapeText(value) ?? value };
  }

  function draftOf(payload: HealthCheckPayload): { encoding: PayloadEncoding; value: string } {
    return 'hex' in payload
      ? { encoding: 'hex', value: payload.hex }
      : { encoding: 'text', value: escapeText(payload.text) };
  }

  function withTimeout(): { timeout_ms?: number } {
    return formProbeTimeout == null ? {} : { timeout_ms: formProbeTimeout };
  }

  /// The check the form sends: the typed shape only, never the
  /// deprecated `health_check_path`.
  function formHealthCheck(): HealthCheck {
    switch (formHealthCheckKind) {
      case 'http':
        return { kind: 'http', path: formHealthCheckPath.trim() };
      case 'tcp_connect':
        return { kind: 'tcp_connect' };
      case 'tcp_template':
        return { kind: 'tcp_template', template: formTemplate, ...withTimeout() };
      case 'tcp_send_expect':
        return {
          kind: 'tcp_send_expect',
          ...(formSend === '' ? {} : { send: payloadOf(formSendEncoding, formSend) }),
          expect: formExpect.map((draft) => ({ match: draft.match, bytes: payloadOf(draft.encoding, draft.value) })),
          ...withTimeout(),
        };
    }
  }

  /// Load a stored check into the form's fields.
  function loadHealthCheck(check: HealthCheck) {
    formHealthCheckKind = check.kind;
    formHealthCheckPath = check.kind === 'http' ? check.path : '';
    formTemplate = TCP_CHECK_TEMPLATES[0].name;
    formProbeTimeout = null;
    formSendEncoding = 'text';
    formSend = '';
    formExpect = [newExpectDraft()];
    if (check.kind === 'tcp_template') {
      formTemplate = check.template;
      formProbeTimeout = check.timeout_ms ?? null;
    } else if (check.kind === 'tcp_send_expect') {
      if (check.send) {
        const send = draftOf(check.send);
        formSendEncoding = send.encoding;
        formSend = send.value;
      }
      formExpect = check.expect.map((answer) => ({ match: answer.match, ...draftOf(answer.bytes) }));
      formProbeTimeout = check.timeout_ms ?? null;
    }
  }

  function describeHealthCheck(check: HealthCheck): string {
    switch (check.kind) {
      case 'http':
        return `HTTP ${check.path}`;
      case 'tcp_connect':
        return 'TCP';
      case 'tcp_template':
        return `TCP ${check.template}`;
      case 'tcp_send_expect':
        return 'TCP send/expect';
    }
  }

  function describeAnswers(template: CheckTemplate): string {
    return template.expect.map((answer) => `${answer.match} ${answer.bytes.shown}`).join(', or ');
  }

  function handleAddressBlur() {
    addressError = validateAddress(formAddress);
  }

  // Blur-time validators for the remaining backend-form fields. The
  // create/update routes also range-check these server-side, but the
  // dashboard should not let the operator blur out of the field still
  // thinking the value is OK.
  let weightError = $state('');
  let hcIntervalError = $state('');
  let hcPathError = $state('');
  function handleWeightBlur() {
    const n = Number(formWeight);
    if (!Number.isInteger(n) || n < 1 || n > 1000) {
      weightError = 'Weight must be an integer in 1..1000';
    } else {
      weightError = '';
    }
  }
  function handleHcIntervalBlur() {
    if (formHealthCheckInterval == null) { hcIntervalError = ''; return; }
    const n = Number(formHealthCheckInterval);
    if (!Number.isInteger(n) || n < 5 || n > 3600) {
      hcIntervalError = 'Interval must be an integer in 5..3600 s';
    } else {
      hcIntervalError = '';
    }
  }
  function handleHcPathBlur() {
    const p = formHealthCheckPath.trim();
    if (p === '') { hcPathError = ''; return; }
    if (!p.startsWith('/')) { hcPathError = "must start with '/'"; return; }
    if (p.length > 1024) { hcPathError = 'must be <= 1024 characters'; return; }
    if (/\s/.test(p)) { hcPathError = 'must not contain whitespace'; return; }
    hcPathError = '';
  }

  async function loadData() {
    loading = true;
    error = '';
    const res = await api.listBackends();
    if (res.error) {
      error = res.error.message;
    } else if (res.data) {
      backends = res.data.backends;
    }
    loading = false;
  }

  onMount(loadData);

  function openCreateForm() {
    editingBackend = null;
    formAddress = '';
    formName = '';
    formGroupName = '';
    formWeight = 100;
    formHealthCheckEnabled = true;
    formHealthCheckInterval = null;
    hcIntervalError = '';
    loadHealthCheck({ kind: 'tcp_connect' });
    hcPathError = '';
    formTlsUpstream = false;
    formTlsSkipVerify = false;
    formTlsSni = '';
    formH2Upstream = false;
    formError = '';
    addressError = '';
    showForm = true;
  }

  function openEditForm(b: BackendResponse) {
    // The button is disabled for a managed backend; this guard covers a
    // keyboard or scripted click that bypasses the attribute.
    if (b.managed_by) return;
    editingBackend = b;
    formAddress = b.address;
    formName = b.name ?? '';
    formGroupName = b.group_name ?? '';
    formWeight = b.weight;
    formHealthCheckEnabled = b.health_check_enabled;
    formHealthCheckInterval = b.health_check_interval_s;
    loadHealthCheck(b.health_check);
    hcPathError = '';
    formTlsUpstream = b.tls_upstream;
    formTlsSkipVerify = b.tls_skip_verify;
    formTlsSni = b.tls_sni ?? '';
    formH2Upstream = b.h2_upstream;
    formError = '';
    addressError = '';
    showForm = true;
  }

  async function handleSubmit() {
    const err = validate();
    if (err) {
      formError = err;
      return;
    }
    formSubmitting = true;
    formError = '';

    if (editingBackend) {
      const body: UpdateBackendRequest = {
        address: formAddress,
        name: formName || undefined,
        group_name: formGroupName || undefined,
        weight: formWeight,
        health_check_enabled: formHealthCheckEnabled,
        health_check_interval_s: formHealthCheckInterval ?? undefined,
        health_check: formHealthCheck(),
        tls_upstream: formTlsUpstream,
        tls_skip_verify: formTlsSkipVerify,
        tls_sni: formTlsSni,
        h2_upstream: formH2Upstream,
      };
      const res = await api.updateBackend(editingBackend.id, body);
      if (res.error) {
        formError = res.error.message;
        formSubmitting = false;
        return;
      }
      showToast('Backend updated', 'success');
    } else {
      const body: CreateBackendRequest = {
        address: formAddress,
        name: formName || undefined,
        group_name: formGroupName || undefined,
        weight: formWeight,
        health_check_enabled: formHealthCheckEnabled,
        health_check_interval_s: formHealthCheckInterval ?? undefined,
        health_check: formHealthCheck(),
        tls_upstream: formTlsUpstream,
        tls_skip_verify: formTlsSkipVerify,
        tls_sni: formTlsSni || undefined,
        h2_upstream: formH2Upstream,
      };
      const res = await api.createBackend(body);
      if (res.error) {
        formError = res.error.message;
        formSubmitting = false;
        return;
      }
      showToast('Backend created', 'success');
    }

    formSubmitting = false;
    showForm = false;
    await loadData();
  }

  function openDeleteDialog(b: BackendResponse) {
    // The button is disabled for a managed backend, and the API answers
    // 409 anyway; this guard covers a keyboard or scripted click.
    if (b.managed_by) return;
    deletingBackend = b;
  }

  function deleteBackendMessage(b: BackendResponse): string {
    return `Delete backend ${b.address}? Routes using this backend will lose it from their pool.`;
  }

  async function handleDelete() {
    if (!deletingBackend) return;
    const res = await api.deleteBackend(deletingBackend.id);
    if (res.error) {
      error = res.error.message;
    } else {
      showToast('Backend deleted', 'success');
    }
    deletingBackend = null;
    await loadData();
  }

  function handleKeydown(e: KeyboardEvent) {
    if (showForm && e.key === 'Escape') showForm = false;
    if (showForm && e.key === 'Enter' && !formSubmitting) handleSubmit();
  }
</script>

<svelte:window onkeydown={handleKeydown} />

<div class="backends-page">
  <div class="page-header">
    <h1>Backends</h1>
    {#if $canWrite}
      <button class="btn btn-primary" onclick={openCreateForm}>Add Backend</button>
    {/if}
  </div>

  {#if error}
    <div class="error-banner">{error}</div>
  {/if}

  {#if loading}
    <p class="loading">Loading backends...</p>
  {:else if backends.length === 0}
    <div class="empty-state">
      <p>No backends configured yet.</p>
      {#if $canWrite}
        <button class="btn btn-primary" onclick={openCreateForm}>Add your first backend</button>
      {/if}
    </div>
  {:else}
    <div class="filter-bar">
      <input type="text" class="search-input" bind:value={searchQuery} placeholder="Search by name, group, or address..." />
    </div>
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th class="sortable" tabindex="0" role="button" onclick={() => toggleSort('name')} onkeydown={(e) => { if (e.key === 'Enter') toggleSort('name'); }}>
              Name {sortColumn === 'name' ? (sortDirection === 'asc' ? '\u2191' : '\u2193') : ''}
            </th>
            <th class="sortable" tabindex="0" role="button" onclick={() => toggleSort('group')} onkeydown={(e) => { if (e.key === 'Enter') toggleSort('group'); }}>
              Group {sortColumn === 'group' ? (sortDirection === 'asc' ? '\u2191' : '\u2193') : ''}
            </th>
            <th class="sortable" tabindex="0" role="button" onclick={() => toggleSort('address')} onkeydown={(e) => { if (e.key === 'Enter') toggleSort('address'); }}>
              Address {sortColumn === 'address' ? (sortDirection === 'asc' ? '\u2191' : '\u2193') : ''}
            </th>
            <th class="sortable" tabindex="0" role="button" onclick={() => toggleSort('health')} onkeydown={(e) => { if (e.key === 'Enter') toggleSort('health'); }}>
              Health {sortColumn === 'health' ? (sortDirection === 'asc' ? '\u2191' : '\u2193') : ''}
            </th>
            <th>Weight</th>
            <th>Health Check</th>
            <th>TLS</th>
            <th>Connections</th>
            <th>EWMA</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each filteredBackends as b (b.id)}
            <tr>
              <td>
                {b.name || '-'}
                {#if b.managed_by}
                  <AutomationBadge managedBy={b.managed_by} />
                {/if}
              </td>
              <td>{b.group_name || '-'}</td>
              <td class="mono">{b.address}</td>
              <td><StatusBadge status={b.health_status as 'healthy' | 'degraded' | 'down' | 'unknown'} /></td>
              <td>{b.weight}</td>
              <td>
                {#if b.health_check_enabled}
                  <span class="badge-on">{describeHealthCheck(b.health_check)}</span>
                  <span class="text-muted small"> / {b.health_check_interval_s}s</span>
                {:else}
                  <span class="text-muted">Disabled</span>
                {/if}
              </td>
              <td>
                {#if b.tls_upstream}
                  <span class="badge-on">TLS</span>
                {:else}
                  <span class="text-muted">Plain</span>
                {/if}
                {#if b.h2_upstream}
                  <span class="badge-on">H2</span>
                {/if}
              </td>
              <td class="mono">{b.active_connections}</td>
              <td class="mono">{b.ewma_score_us > 0 ? `${(b.ewma_score_us / 1000).toFixed(1)}ms` : '-'}</td>
              <td class="actions">
                {#if $canWrite}
                  <button
                    class="btn-icon"
                    onclick={() => openEditForm(b)}
                    title={b.managed_by ? managedEditHint(b.managed_by) : 'Edit'}
                    aria-label="Edit {b.name || b.address}"
                    disabled={!!b.managed_by}
                  >
                    <!-- eslint-disable-next-line svelte/no-at-html-tags -->
                    {@html editIcon}
                  </button>
                  <button
                    class="btn-icon btn-icon-danger"
                    onclick={() => openDeleteDialog(b)}
                    title={b.managed_by ? managedDeleteHint(b.managed_by) : 'Delete'}
                    aria-label="Delete {b.name || b.address}"
                    disabled={!!b.managed_by}
                  >
                    <!-- eslint-disable-next-line svelte/no-at-html-tags -->
                    {@html trashIcon}
                  </button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  {#if deletingBackend}
    <ConfirmDialog
      title="Delete Backend"
      message={deleteBackendMessage(deletingBackend)}
      confirmLabel="Delete"
      onconfirm={handleDelete}
      oncancel={() => (deletingBackend = null)}
    />
  {/if}

  {#if showForm}
    <div class="overlay" role="dialog" aria-modal="true" tabindex="-1" onclick={(e) => { if (e.target === e.currentTarget) showForm = false; }} onkeydown={(e) => { if (e.key === 'Escape') showForm = false; }}>
      <div class="modal">
        <h2>{editingBackend ? 'Edit Backend' : 'Add Backend'}</h2>

        {#if formError}
          <div class="form-error">{formError}</div>
        {/if}

        <div class="form-row">
          <div class="form-group">
            <label for="backend-name">Name</label>
            <input id="backend-name" type="text" bind:value={formName} placeholder="e.g. web-server-01, wazuh-node" />
          </div>
          <div class="form-group">
            <label for="backend-group">Group</label>
            <input id="backend-group" type="text" bind:value={formGroupName} placeholder="e.g. kubernetes, production, dmz" />
          </div>
        </div>

        <div class="form-group">
          <label for="backend-address">Address <span class="required">*</span></label>
          <input id="backend-address" type="text" bind:value={formAddress} placeholder="10.0.0.1:8080" pattern={'^[a-zA-Z0-9._-]+:\\d{1,5}$'} onblur={handleAddressBlur} oninput={handleAddressBlur} />
          {#if addressError}
            <span class="field-error">{addressError}</span>
          {/if}
        </div>

        <div class="form-row">
          <div class="form-group">
            <label for="backend-weight">Weight</label>
            <input id="backend-weight" type="number" bind:value={formWeight} min="1" max="1000" onblur={handleWeightBlur} oninput={handleWeightBlur} />
            {#if weightError}<span class="field-error">{weightError}</span>{/if}
          </div>
          <div class="form-group">
            <label for="backend-healthcheck-interval">Health Check Interval (s)</label>
            <input id="backend-healthcheck-interval" type="number" bind:value={formHealthCheckInterval} min="5" max="3600" placeholder="Default (Settings)" onblur={handleHcIntervalBlur} oninput={handleHcIntervalBlur} />
            {#if hcIntervalError}<span class="field-error">{hcIntervalError}</span>{/if}
          </div>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label for="backend-healthcheck-kind">Health Check Type</label>
            <select id="backend-healthcheck-kind" bind:value={formHealthCheckKind}>
              <option value="tcp_connect">TCP connect</option>
              <option value="http">HTTP GET (HTTP routes only)</option>
              <option value="tcp_template">TCP protocol template</option>
              <option value="tcp_send_expect">TCP send/expect (custom bytes)</option>
            </select>
          </div>
          {#if formHealthCheckKind === 'http'}
            <div class="form-group">
              <label for="backend-healthcheck-path">Health Check Path <span class="required">*</span></label>
              <input id="backend-healthcheck-path" type="text" bind:value={formHealthCheckPath} placeholder="/healthz" onblur={handleHcPathBlur} oninput={handleHcPathBlur} />
              {#if hcPathError}<span class="field-error">{hcPathError}</span>{/if}
            </div>
          {:else if formHealthCheckKind === 'tcp_template'}
            <div class="form-group">
              <label for="backend-healthcheck-template">Template</label>
              <select id="backend-healthcheck-template" bind:value={formTemplate}>
                {#each TCP_CHECK_TEMPLATES as template (template.name)}
                  <option value={template.name}>{template.name}</option>
                {/each}
              </select>
            </div>
          {/if}
        </div>

        {#if formHealthCheckKind === 'tcp_template' && selectedTemplate}
          <div class="template-bytes" data-testid="template-bytes">
            <p class="hint">{selectedTemplate.summary}</p>
            <p class="hint">
              Sends {#if selectedTemplate.send}<code>{selectedTemplate.send.shown}</code>{:else}nothing{/if};
              expects {describeAnswers(selectedTemplate)}.
            </p>
          </div>
        {/if}

        {#if formHealthCheckKind === 'tcp_send_expect'}
          <fieldset class="exchange">
            <legend>Send/expect exchange (plaintext TCP)</legend>
            <div class="form-row">
              <div class="form-group">
                <label for="backend-healthcheck-send">Send</label>
                <input id="backend-healthcheck-send" type="text" class="mono" bind:value={formSend} placeholder={formSendEncoding === 'hex' ? '0000000804d2162f' : 'PING\\r\\n'} />
              </div>
              <div class="form-group encoding">
                <label for="backend-healthcheck-send-encoding">Send as</label>
                <select id="backend-healthcheck-send-encoding" bind:value={formSendEncoding}>
                  <option value="text">Text</option>
                  <option value="hex">Hex</option>
                </select>
              </div>
            </div>
            <span class="hint">
              Leave empty to send nothing. Text takes the escapes \r, \n, \t and \\; use hex for any
              other byte. At most {SEND_MAX_BYTES} bytes. Never put a credential here: it is stored in
              clear and shown to every operator.
            </span>

            <p class="exchange-label">Healthy when the backend answers, any of (at most {EXPECT_MAX_ALTERNATIVES}, {EXPECT_MAX_BYTES} bytes each):</p>
            {#each formExpect as answer, index (index)}
              <div class="answer-row">
                <select aria-label="Answer {index + 1} match" bind:value={answer.match}>
                  <option value="prefix">starts with</option>
                  <option value="contains">contains</option>
                </select>
                <input type="text" class="mono" aria-label="Answer {index + 1} bytes" bind:value={answer.value} />
                <select aria-label="Answer {index + 1} encoding" bind:value={answer.encoding}>
                  <option value="text">Text</option>
                  <option value="hex">Hex</option>
                </select>
                <button type="button" class="link-btn" aria-label="Remove answer {index + 1}" disabled={formExpect.length === 1} onclick={() => { formExpect = formExpect.filter((_, i) => i !== index); }}>Remove</button>
              </div>
            {/each}
            <button type="button" class="btn btn-secondary" disabled={formExpect.length >= EXPECT_MAX_ALTERNATIVES} onclick={() => { formExpect = [...formExpect, newExpectDraft()]; }}>Add an answer</button>
          </fieldset>
        {/if}

        {#if formHealthCheckKind === 'tcp_template' || formHealthCheckKind === 'tcp_send_expect'}
          <div class="form-group">
            <label for="backend-healthcheck-timeout">Probe Timeout (ms)</label>
            <input id="backend-healthcheck-timeout" type="number" bind:value={formProbeTimeout} min={PROBE_TIMEOUT_MS_MIN} max={PROBE_TIMEOUT_MS_MAX} placeholder="Default ({PROBE_TIMEOUT_MS_DEFAULT})" />
            <span class="hint">Connect, send and read within this deadline, {PROBE_TIMEOUT_MS_MIN} to {PROBE_TIMEOUT_MS_MAX} ms.</span>
          </div>
        {/if}

        <div class="checkbox-row">
          <label class="checkbox-item">
            <input type="checkbox" bind:checked={formHealthCheckEnabled} />
            Health check enabled
          </label>
          <label class="checkbox-item">
            <input type="checkbox" bind:checked={formTlsUpstream} />
            TLS upstream (HTTP routes only; streams ignore it)
          </label>
          <label class="checkbox-item">
            <input type="checkbox" bind:checked={formH2Upstream} />
            HTTP/2 upstream (h2c for plaintext, ALPN h2 for TLS; HTTP routes only; streams ignore it)
          </label>
        </div>

        {#if formTlsUpstream}
          <div class="form-group">
            <label class="checkbox-item">
              <input type="checkbox" bind:checked={formTlsSkipVerify} />
              Skip TLS verification (self-signed certificates; HTTP routes only; streams ignore it)
            </label>
          </div>
          <div class="form-group">
            <label for="form-tls-sni">TLS SNI override (HTTP routes only; streams ignore it)</label>
            <input id="form-tls-sni" type="text" bind:value={formTlsSni} placeholder="Leave empty to use route hostname" />
            <span class="hint">Override the server name sent during TLS handshake to the backend</span>
          </div>
        {/if}

        <div class="form-actions">
          <button class="btn btn-cancel" onclick={() => (showForm = false)}>Cancel</button>
          <button class="btn btn-primary" onclick={handleSubmit} disabled={formSubmitting}>
            {formSubmitting ? 'Saving...' : editingBackend ? 'Update' : 'Create'}
          </button>
        </div>
      </div>
    </div>
  {/if}
</div>

<script lang="ts" module>
  const editIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>';
  const trashIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>';
</script>

<style>
  .backends-page { max-width: none; }
  .badge-on { display: inline-block; padding: 0.125rem 0.5rem; border-radius: var(--radius-full); font-size: var(--text-sm); font-weight: 500; background: var(--color-green-subtle); color: var(--color-green-text); }
  .field-error { display: block; color: var(--color-red); font-size: var(--text-xs); margin-top: 0.25rem; }
  .filter-bar { margin-bottom: var(--space-4); }
  .search-input { width: 100%; max-width: 400px; padding: var(--space-2) var(--space-3); border: 1px solid var(--color-border); border-radius: var(--radius-md); background: var(--color-bg-input); color: var(--color-text); font-size: var(--text-md); }
  .search-input:focus { outline: none; border-color: var(--color-primary); box-shadow: 0 0 0 3px var(--color-primary-subtle); }
  .sortable { cursor: pointer; user-select: none; }
  .sortable:hover { color: var(--color-text-heading); }
  .checkbox-row { display: flex; flex-wrap: wrap; gap: var(--space-4) var(--space-6); margin-top: var(--space-2); margin-bottom: var(--space-4); }
  .checkbox-row .checkbox-item { white-space: nowrap; }
  /* A managed row keeps its action buttons visible but inert, so the
     operator reads the tooltip instead of wondering where Edit went. */
  .btn-icon:disabled { opacity: 0.4; cursor: not-allowed; }
  .btn-icon:disabled:hover { background: none; color: var(--color-text-muted); }
  .template-bytes { margin-bottom: var(--space-4); }
  .template-bytes code { font-family: var(--font-mono, monospace); }
  .exchange { border: 1px solid var(--color-border); border-radius: var(--radius-md); padding: var(--space-3) var(--space-4); margin: 0 0 var(--space-4); }
  .exchange legend { padding: 0 var(--space-2); font-size: var(--text-sm); color: var(--color-text-muted); }
  .exchange .encoding { flex: 0 0 auto; }
  .exchange-label { margin: var(--space-3) 0 var(--space-2); font-size: var(--text-sm); }
  .answer-row { display: flex; gap: var(--space-2); align-items: center; margin-bottom: var(--space-2); }
  .answer-row input { flex: 1; min-width: 0; }
</style>
