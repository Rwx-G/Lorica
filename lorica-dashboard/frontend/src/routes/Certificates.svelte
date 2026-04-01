<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    type CertificateResponse,
    type CertificateDetailResponse,
    type RouteResponse,
    type CreateCertificateRequest,
    type UpdateCertificateRequest,
    type GenerateSelfSignedRequest,
    type AcmeProvisionRequest,
    type AcmeDnsProvisionRequest,
    type AcmeDnsManualRequest,
    type AcmeDnsManualConfirmRequest,
  } from '../lib/api';
  import CertExpiryBadge from '../components/CertExpiryBadge.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';

  let certificates: CertificateResponse[] = $state([]);
  let routes: RouteResponse[] = $state([]);
  let error = $state('');
  let loading = $state(true);

  // Threshold configuration
  let warningDays = $state(30);
  let criticalDays = $state(7);
  let showThresholdConfig = $state(false);
  let thresholdWarning = $state(30);
  let thresholdCritical = $state(7);

  // Upload form state
  let showUploadForm = $state(false);
  let formDomain = $state('');
  let formCertPem = $state('');
  let formKeyPem = $state('');
  let formError = $state('');
  let formSubmitting = $state(false);

  // Edit form state
  let editingCert: CertificateResponse | null = $state(null);
  let showEditForm = $state(false);
  let editDomain = $state('');
  let editCertPem = $state('');
  let editKeyPem = $state('');
  let editError = $state('');
  let editSubmitting = $state(false);

  // Detail view state
  let detailCert: CertificateDetailResponse | null = $state(null);
  let showDetail = $state(false);
  let detailLoading = $state(false);

  // Delete state
  let deletingCert: CertificateResponse | null = $state(null);
  let deleteRoutes: RouteResponse[] = $state([]);

  // Self-signed generation state
  let showSelfSigned = $state(false);
  let selfSignedDomain = $state('');
  let selfSignedError = $state('');
  let selfSignedSubmitting = $state(false);
  let selfSignedPref: 'never' | 'always' | 'once' | null = $state(null);
  let selfSignedPrefId: string | null = $state(null);
  let showSelfSignedPrefPrompt = $state(false);

  // ACME provisioning state
  let showAcmeForm = $state(false);
  let acmeMode: 'http01' | 'dns01' | 'dns01-manual' = $state('http01');
  let acmeDomain = $state('');
  let acmeEmail = $state('');
  let acmeStaging = $state(false);
  let acmeDnsProvider = $state('cloudflare');
  let acmeDnsZoneId = $state('');
  let acmeDnsApiToken = $state('');
  let acmeDnsApiSecret = $state('');
  let acmeError = $state('');
  let acmeSubmitting = $state(false);
  let acmeSuccess = $state('');
  // Manual DNS-01 two-step state
  let manualTxtName = $state('');
  let manualTxtValue = $state('');
  let manualPendingDomain = $state('');
  let manualStep: 1 | 2 = $state(1);
  let manualCopied = $state('');

  function openAcmeForm() {
    acmeDomain = '';
    acmeEmail = '';
    acmeStaging = false;
    acmeMode = 'http01';
    acmeDnsProvider = 'cloudflare';
    acmeDnsZoneId = '';
    acmeDnsApiToken = '';
    acmeDnsApiSecret = '';
    acmeError = '';
    acmeSuccess = '';
    manualTxtName = '';
    manualTxtValue = '';
    manualPendingDomain = '';
    manualStep = 1;
    manualCopied = '';
    showAcmeForm = true;
  }

  async function copyToClipboard(text: string, label: string) {
    try {
      await navigator.clipboard.writeText(text);
      manualCopied = label;
      setTimeout(() => { manualCopied = ''; }, 2000);
    } catch {
      // Fallback: select the text
      manualCopied = '';
    }
  }

  async function handleAcmeProvision() {
    if (!acmeDomain.trim()) {
      acmeError = 'Domain is required';
      return;
    }
    acmeSubmitting = true;
    acmeError = '';
    acmeSuccess = '';

    if (acmeMode === 'http01') {
      const body: AcmeProvisionRequest = {
        domain: acmeDomain,
        staging: acmeStaging,
        contact_email: acmeEmail || undefined,
      };
      const res = await api.provisionAcme(body);
      acmeSubmitting = false;
      if (res.error) {
        acmeError = res.error.message;
      } else if (res.data) {
        acmeSuccess = res.data.message;
        await loadData();
      }
    } else if (acmeMode === 'dns01') {
      if (!acmeDnsZoneId.trim() || !acmeDnsApiToken.trim()) {
        acmeError = 'Zone ID and API token are required for DNS-01';
        acmeSubmitting = false;
        return;
      }
      const body: AcmeDnsProvisionRequest = {
        domain: acmeDomain,
        staging: acmeStaging,
        contact_email: acmeEmail || undefined,
        dns: {
          provider: acmeDnsProvider,
          zone_id: acmeDnsZoneId,
          api_token: acmeDnsApiToken,
          api_secret: acmeDnsApiSecret || undefined,
        },
      };
      const res = await api.provisionAcmeDns(body);
      acmeSubmitting = false;
      if (res.error) {
        acmeError = res.error.message;
      } else if (res.data) {
        acmeSuccess = res.data.message;
        await loadData();
      }
    } else if (acmeMode === 'dns01-manual') {
      // Step 1: get the TXT record info
      const body: AcmeDnsManualRequest = {
        domain: acmeDomain,
        staging: acmeStaging,
        contact_email: acmeEmail || undefined,
      };
      const res = await api.provisionAcmeDnsManual(body);
      acmeSubmitting = false;
      if (res.error) {
        acmeError = res.error.message;
      } else if (res.data) {
        manualTxtName = res.data.txt_record_name;
        manualTxtValue = res.data.txt_record_value;
        manualPendingDomain = res.data.domain;
        manualStep = 2;
      }
    }
  }

  async function handleManualDnsConfirm() {
    acmeSubmitting = true;
    acmeError = '';
    const body: AcmeDnsManualConfirmRequest = { domain: manualPendingDomain };
    const res = await api.confirmAcmeDnsManual(body);
    acmeSubmitting = false;
    if (res.error) {
      acmeError = res.error.message;
    } else if (res.data) {
      acmeSuccess = res.data.message;
      manualStep = 1;
      manualTxtName = '';
      manualTxtValue = '';
      manualPendingDomain = '';
      await loadData();
    }
  }

  async function loadData() {
    loading = true;
    error = '';
    const [certsRes, routesRes, settingsRes, prefRes] = await Promise.all([
      api.listCertificates(),
      api.listRoutes(),
      api.getSettings(),
      api.listPreferences(),
    ]);
    if (certsRes.error) {
      error = certsRes.error.message;
    } else if (certsRes.data) {
      certificates = certsRes.data.certificates;
    }
    if (routesRes.data) {
      routes = routesRes.data.routes;
    }
    if (settingsRes.data) {
      warningDays = settingsRes.data.cert_warning_days;
      criticalDays = settingsRes.data.cert_critical_days;
    }
    if (prefRes.data) {
      const ssPref = prefRes.data.preferences.find((p) => p.preference_key === 'self_signed_cert');
      if (ssPref) {
        selfSignedPref = ssPref.value as 'never' | 'always' | 'once';
        selfSignedPrefId = ssPref.id;
      }
    }
    loading = false;
  }

  onMount(loadData);

  function formatDate(iso: string): string {
    return new Date(iso).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  }

  function getRoutesForCert(certId: string): RouteResponse[] {
    return routes.filter((r) => r.certificate_id === certId);
  }

  // Upload form
  function openUploadForm() {
    formDomain = '';
    formCertPem = '';
    formKeyPem = '';
    formError = '';
    showUploadForm = true;
  }

  function closeUploadForm() {
    showUploadForm = false;
  }

  function handleUploadKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') closeUploadForm();
  }

  async function handleFileInput(
    e: Event,
    target: 'cert' | 'key',
  ) {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    const text = await file.text();
    if (target === 'cert') formCertPem = text;
    else formKeyPem = text;
  }

  const DOMAIN_PATTERN = /^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/;

  function validateUploadForm(): string {
    if (!formDomain.trim()) return 'Domain is required';
    if (!DOMAIN_PATTERN.test(formDomain.trim())) return 'Invalid domain pattern';
    if (!formCertPem.trim()) return 'Certificate PEM is required';
    if (!formCertPem.trim().startsWith('-----BEGIN CERTIFICATE-----')) return 'Certificate PEM must start with -----BEGIN CERTIFICATE-----';
    if (!formKeyPem.trim()) return 'Private key PEM is required';
    if (!formKeyPem.trim().startsWith('-----BEGIN')) return 'Key PEM must start with -----BEGIN (RSA/EC/PRIVATE KEY)';
    return '';
  }

  async function handleUploadSubmit() {
    const err = validateUploadForm();
    if (err) {
      formError = err;
      return;
    }
    formSubmitting = true;
    formError = '';

    const body: CreateCertificateRequest = {
      domain: formDomain,
      cert_pem: formCertPem,
      key_pem: formKeyPem,
    };
    const res = await api.createCertificate(body);
    if (res.error) {
      formError = res.error.message;
      formSubmitting = false;
      return;
    }

    formSubmitting = false;
    closeUploadForm();
    await loadData();
  }

  // Edit form
  function openEditForm(cert: CertificateResponse) {
    editingCert = cert;
    editDomain = cert.domain;
    editCertPem = '';
    editKeyPem = '';
    editError = '';
    showEditForm = true;
  }

  function closeEditForm() {
    showEditForm = false;
    editingCert = null;
  }

  function handleEditKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') closeEditForm();
  }

  function validateEditForm(): string {
    if (editDomain.trim() && !DOMAIN_PATTERN.test(editDomain.trim())) return 'Invalid domain pattern';
    if (editCertPem.trim() && !editCertPem.trim().startsWith('-----BEGIN CERTIFICATE-----')) {
      return 'Certificate PEM must start with -----BEGIN CERTIFICATE-----';
    }
    if (editKeyPem.trim() && !editKeyPem.trim().startsWith('-----BEGIN')) {
      return 'Key PEM must start with -----BEGIN (RSA/EC/PRIVATE KEY)';
    }
    return '';
  }

  async function handleEditSubmit() {
    if (!editingCert) return;
    const valErr = validateEditForm();
    if (valErr) {
      editError = valErr;
      return;
    }
    editSubmitting = true;
    editError = '';

    const body: UpdateCertificateRequest = {};
    if (editDomain !== editingCert.domain) body.domain = editDomain;
    if (editCertPem.trim()) body.cert_pem = editCertPem;
    if (editKeyPem.trim()) body.key_pem = editKeyPem;

    if (!body.domain && !body.cert_pem && !body.key_pem) {
      editError = 'No changes to save';
      editSubmitting = false;
      return;
    }

    const res = await api.updateCertificate(editingCert.id, body);
    if (res.error) {
      editError = res.error.message;
      editSubmitting = false;
      return;
    }

    editSubmitting = false;
    closeEditForm();
    await loadData();
  }

  // Detail view
  async function openDetail(cert: CertificateResponse) {
    detailLoading = true;
    showDetail = true;
    detailCert = null;
    const res = await api.getCertificate(cert.id);
    if (res.error) {
      error = res.error.message;
      showDetail = false;
    } else if (res.data) {
      detailCert = res.data;
    }
    detailLoading = false;
  }

  function closeDetail() {
    showDetail = false;
    detailCert = null;
  }

  function handleDetailKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') closeDetail();
  }

  function getRouteHostname(routeId: string): string {
    const r = routes.find((r) => r.id === routeId);
    return r ? `${r.hostname}${r.path_prefix}` : routeId.slice(0, 8);
  }

  // Delete
  function openDelete(cert: CertificateResponse) {
    deletingCert = cert;
    deleteRoutes = getRoutesForCert(cert.id);
  }

  async function handleDelete() {
    if (!deletingCert) return;
    const res = await api.deleteCertificate(deletingCert.id);
    if (res.error) {
      error = res.error.message;
    }
    deletingCert = null;
    deleteRoutes = [];
    await loadData();
  }

  function deleteMessage(): string {
    if (!deletingCert) return '';
    const base = `Are you sure you want to delete the certificate for "${deletingCert.domain}"?`;
    if (deleteRoutes.length === 0) {
      return `${base} No routes are using this certificate.`;
    }
    const routeNames = deleteRoutes.map((r) => `${r.hostname}${r.path_prefix}`).join(', ');
    return `${base} WARNING: ${deleteRoutes.length} route(s) will lose TLS: ${routeNames}. Deletion will be blocked by the server if routes still reference this certificate.`;
  }

  // Self-signed generation
  function openSelfSigned() {
    if (selfSignedPref === 'never') return;
    if (selfSignedPref === null) {
      showSelfSignedPrefPrompt = true;
      return;
    }
    selfSignedDomain = '';
    selfSignedError = '';
    showSelfSigned = true;
  }

  async function handleSelfSignedPref(choice: 'never' | 'always' | 'once') {
    selfSignedPref = choice;
    showSelfSignedPrefPrompt = false;
    if (selfSignedPrefId) {
      await api.updatePreference(selfSignedPrefId, choice);
    }
    if (choice === 'never') return;
    selfSignedDomain = '';
    selfSignedError = '';
    showSelfSigned = true;
  }

  function closeSelfSigned() {
    showSelfSigned = false;
  }

  function handleSelfSignedKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') closeSelfSigned();
  }

  async function handleSelfSignedSubmit() {
    if (!selfSignedDomain.trim()) {
      selfSignedError = 'Domain is required';
      return;
    }
    selfSignedSubmitting = true;
    selfSignedError = '';

    const body: GenerateSelfSignedRequest = {
      domain: selfSignedDomain,
    };
    const res = await api.generateSelfSigned(body);
    if (res.error) {
      selfSignedError = res.error.message;
      selfSignedSubmitting = false;
      return;
    }

    selfSignedSubmitting = false;
    closeSelfSigned();
    if (selfSignedPref === 'once') {
      selfSignedPref = null;
    }
    await loadData();
  }

  // Threshold config
  function openThresholdConfig() {
    thresholdWarning = warningDays;
    thresholdCritical = criticalDays;
    showThresholdConfig = true;
  }

  function closeThresholdConfig() {
    showThresholdConfig = false;
  }

  function handleThresholdKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') closeThresholdConfig();
  }

  async function saveThresholds() {
    if (thresholdCritical >= thresholdWarning) {
      return;
    }
    warningDays = thresholdWarning;
    criticalDays = thresholdCritical;
    await api.updateSettings({ cert_warning_days: warningDays, cert_critical_days: criticalDays });
    closeThresholdConfig();
  }
</script>

<div class="certs-page">
  <div class="page-header">
    <h1>Certificates</h1>
    <div class="header-actions">
      <button class="btn btn-secondary" onclick={openThresholdConfig} title="Configure expiration thresholds">
        {@html gearIcon}
      </button>
      <button class="btn btn-secondary" onclick={openSelfSigned}>Self-signed</button>
      <button class="btn btn-acme" onclick={openAcmeForm}>Let's Encrypt</button>
      <button class="btn btn-primary" onclick={openUploadForm}>+ Upload Certificate</button>
    </div>
  </div>

  {#if error}
    <div class="error-banner">{error}</div>
  {/if}

  {#if loading}
    <p class="loading">Loading...</p>
  {:else if certificates.length === 0}
    <div class="empty-state">
      <p>No certificates configured yet.</p>
      <button class="btn btn-primary" onclick={openUploadForm}>Upload your first certificate</button>
    </div>
  {:else}
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Domain</th>
            <th>Issuer</th>
            <th>Expires</th>
            <th>Days Left</th>
            <th>Status</th>
            <th>Routes</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each certificates as cert (cert.id)}
            <tr>
              <td class="domain">
                <button class="link-btn" onclick={() => openDetail(cert)}>{cert.domain}</button>
                {#if cert.san_domains.length > 0}
                  <span class="san-count" title={cert.san_domains.join(', ')}>+{cert.san_domains.length} SAN</span>
                {/if}
              </td>
              <td class="issuer">{cert.issuer}</td>
              <td>{formatDate(cert.not_after)}</td>
              <td>
                {#if true}
                  {@const daysLeft = Math.ceil((new Date(cert.not_after).getTime() - Date.now()) / (1000 * 60 * 60 * 24))}
                  <span class="days-left" style="color: {daysLeft < 7 ? 'var(--color-red)' : daysLeft <= 30 ? 'var(--color-orange, #fb923c)' : 'var(--color-green)'}; font-weight: 700; font-size: 1rem;">
                    {daysLeft}d
                  </span>
                {/if}
              </td>
              <td><CertExpiryBadge notAfter={cert.not_after} {warningDays} {criticalDays} /></td>
              <td>
                {#if getRoutesForCert(cert.id).length === 0}
                  <span class="text-muted">None</span>
                {:else}
                  <span class="route-count">{getRoutesForCert(cert.id).length} route{getRoutesForCert(cert.id).length > 1 ? 's' : ''}</span>
                {/if}
              </td>
              <td class="actions">
                <button class="btn-icon" title="View details" onclick={() => openDetail(cert)}>
                  {@html eyeIcon}
                </button>
                <button class="btn-icon" title="Edit" onclick={() => openEditForm(cert)}>
                  {@html editIcon}
                </button>
                <button class="btn-icon btn-icon-danger" title="Delete" onclick={() => openDelete(cert)}>
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

<!-- Upload Form Modal -->
{#if showUploadForm}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="overlay" onclick={closeUploadForm} onkeydown={handleUploadKeydown} role="dialog" aria-modal="true" tabindex="-1">
    <div class="modal" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="document">
      <h2>Upload Certificate</h2>

      {#if formError}
        <div class="form-error">{formError}</div>
      {/if}

      <div class="form-group">
        <label for="upload-domain">Domain <span class="required">*</span></label>
        <input id="upload-domain" type="text" bind:value={formDomain} placeholder="example.com" />
      </div>

      <div class="form-group">
        <label for="upload-cert">Certificate PEM <span class="required">*</span></label>
        <div class="file-input-row">
          <input type="file" accept=".pem,.crt,.cer" onchange={(e) => handleFileInput(e, 'cert')} />
        </div>
        <textarea id="upload-cert" bind:value={formCertPem} placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----" rows="4"></textarea>
      </div>

      <div class="form-group">
        <label for="upload-key">Private Key PEM <span class="required">*</span></label>
        <div class="file-input-row">
          <input type="file" accept=".pem,.key" onchange={(e) => handleFileInput(e, 'key')} />
        </div>
        <textarea id="upload-key" bind:value={formKeyPem} placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----" rows="4"></textarea>
      </div>

      <div class="form-actions">
        <button class="btn btn-cancel" onclick={closeUploadForm}>Cancel</button>
        <button class="btn btn-primary" disabled={formSubmitting} onclick={handleUploadSubmit}>
          {formSubmitting ? 'Uploading...' : 'Upload'}
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- Edit Form Modal -->
{#if showEditForm && editingCert}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="overlay" onclick={closeEditForm} onkeydown={handleEditKeydown} role="dialog" aria-modal="true" tabindex="-1">
    <div class="modal" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="document">
      <h2>Edit Certificate</h2>

      {#if editError}
        <div class="form-error">{editError}</div>
      {/if}

      <div class="form-group">
        <label for="edit-domain">Domain</label>
        <input id="edit-domain" type="text" bind:value={editDomain} />
      </div>

      <div class="form-group">
        <label for="edit-cert">Replace Certificate PEM (optional)</label>
        <textarea id="edit-cert" bind:value={editCertPem} placeholder="Leave empty to keep current certificate" rows="4"></textarea>
      </div>

      <div class="form-group">
        <label for="edit-key">Replace Private Key PEM (optional)</label>
        <textarea id="edit-key" bind:value={editKeyPem} placeholder="Leave empty to keep current key" rows="4"></textarea>
      </div>

      <div class="form-actions">
        <button class="btn btn-cancel" onclick={closeEditForm}>Cancel</button>
        <button class="btn btn-primary" disabled={editSubmitting} onclick={handleEditSubmit}>
          {editSubmitting ? 'Saving...' : 'Update'}
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- Detail View Modal -->
{#if showDetail}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="overlay" onclick={closeDetail} onkeydown={handleDetailKeydown} role="dialog" aria-modal="true" tabindex="-1">
    <div class="modal modal-wide" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="document">
      {#if detailLoading}
        <p class="loading">Loading certificate details...</p>
      {:else if detailCert}
        <h2>Certificate: {detailCert.domain}</h2>

        <div class="detail-grid">
          <div class="detail-row">
            <span class="detail-label">Domain</span>
            <span class="detail-value">{detailCert.domain}</span>
          </div>
          {#if detailCert.san_domains.length > 0}
            <div class="detail-row">
              <span class="detail-label">SAN Domains</span>
              <span class="detail-value">{detailCert.san_domains.join(', ')}</span>
            </div>
          {/if}
          <div class="detail-row">
            <span class="detail-label">Issuer</span>
            <span class="detail-value">{detailCert.issuer}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Valid From</span>
            <span class="detail-value">{formatDate(detailCert.not_before)}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Valid Until</span>
            <span class="detail-value">
              {formatDate(detailCert.not_after)}
              <CertExpiryBadge notAfter={detailCert.not_after} {warningDays} {criticalDays} />
            </span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Fingerprint (SHA-256)</span>
            <span class="detail-value mono">{detailCert.fingerprint}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">ACME</span>
            <span class="detail-value">{detailCert.is_acme ? 'Yes' : 'No'}{detailCert.acme_auto_renew ? ' (auto-renew)' : ''}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Created</span>
            <span class="detail-value">{formatDate(detailCert.created_at)}</span>
          </div>
        </div>

        <div class="detail-section">
          <h3>Associated Routes</h3>
          {#if detailCert.associated_routes.length === 0}
            <p class="text-muted">No routes are using this certificate.</p>
          {:else}
            <ul class="route-list">
              {#each detailCert.associated_routes as routeId}
                <li>{getRouteHostname(routeId)}</li>
              {/each}
            </ul>
          {/if}
        </div>

        <div class="detail-section">
          <h3>Certificate Chain (PEM)</h3>
          <pre class="pem-block">{detailCert.cert_pem}</pre>
        </div>

        <div class="form-actions">
          <button class="btn btn-cancel" onclick={closeDetail}>Close</button>
        </div>
      {/if}
    </div>
  </div>
{/if}

<!-- Delete Confirmation -->
{#if deletingCert}
  <ConfirmDialog
    title="Delete Certificate"
    message={deleteMessage()}
    onconfirm={handleDelete}
    oncancel={() => { deletingCert = null; deleteRoutes = []; }}
  />
{/if}

<!-- Self-signed Preference Prompt -->
{#if showSelfSignedPrefPrompt}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="overlay" onclick={() => { showSelfSignedPrefPrompt = false; }} onkeydown={(e) => { if (e.key === 'Escape') showSelfSignedPrefPrompt = false; }} role="dialog" aria-modal="true" tabindex="-1">
    <div class="modal" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="document">
      <h2>Self-signed Certificate Generation</h2>
      <p class="pref-text">Self-signed certificates are useful for development and testing but should not be used in production. How would you like to handle this?</p>
      <div class="pref-actions">
        <button class="btn btn-cancel" onclick={() => handleSelfSignedPref('never')}>Never generate</button>
        <button class="btn btn-secondary" onclick={() => handleSelfSignedPref('once')}>Just this once</button>
        <button class="btn btn-primary" onclick={() => handleSelfSignedPref('always')}>Always allow</button>
      </div>
    </div>
  </div>
{/if}

<!-- Self-signed Generation Modal -->
{#if showSelfSigned}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="overlay" onclick={closeSelfSigned} onkeydown={handleSelfSignedKeydown} role="dialog" aria-modal="true" tabindex="-1">
    <div class="modal" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="document">
      <h2>Generate Self-signed Certificate</h2>

      {#if selfSignedError}
        <div class="form-error">{selfSignedError}</div>
      {/if}

      <div class="form-group">
        <label for="selfsign-domain">Domain <span class="required">*</span></label>
        <input id="selfsign-domain" type="text" bind:value={selfSignedDomain} placeholder="localhost" />
      </div>

      <div class="form-actions">
        <button class="btn btn-cancel" onclick={closeSelfSigned}>Cancel</button>
        <button class="btn btn-primary" disabled={selfSignedSubmitting} onclick={handleSelfSignedSubmit}>
          {selfSignedSubmitting ? 'Generating...' : 'Generate'}
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- Threshold Configuration Modal -->
{#if showThresholdConfig}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="overlay" onclick={closeThresholdConfig} onkeydown={handleThresholdKeydown} role="dialog" aria-modal="true" tabindex="-1">
    <div class="modal" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="document">
      <h2>Expiration Thresholds</h2>

      <div class="form-group">
        <label for="thresh-warn">Warning threshold (days)</label>
        <input id="thresh-warn" type="number" min="1" bind:value={thresholdWarning} />
        <span class="field-hint">Certificates expiring within this many days show orange.</span>
      </div>

      <div class="form-group">
        <label for="thresh-crit">Critical threshold (days)</label>
        <input id="thresh-crit" type="number" min="1" bind:value={thresholdCritical} />
        <span class="field-hint">Certificates expiring within this many days show red.</span>
      </div>

      {#if thresholdCritical >= thresholdWarning}
        <div class="form-error">Critical threshold must be less than warning threshold.</div>
      {/if}

      <div class="form-actions">
        <button class="btn btn-cancel" onclick={closeThresholdConfig}>Cancel</button>
        <button class="btn btn-primary" disabled={thresholdCritical >= thresholdWarning} onclick={saveThresholds}>Save</button>
      </div>
    </div>
  </div>
{/if}

<!-- ACME Provisioning Modal -->
{#if showAcmeForm}
  <div class="overlay" role="dialog" onclick={(e) => { if (e.target === e.currentTarget) showAcmeForm = false; }}>
    <div class="modal" onclick={(e) => e.stopPropagation()}>
      <h2>Let's Encrypt Certificate</h2>

      {#if acmeSuccess}
        <div class="success-banner">{acmeSuccess}</div>
        <div class="form-actions">
          <button class="btn btn-primary" onclick={() => (showAcmeForm = false)}>Close</button>
        </div>
      {:else if acmeMode === 'dns01-manual' && manualStep === 2}
        <!-- Manual DNS-01 Step 2: show TXT record and confirm -->
        {#if acmeError}
          <div class="form-error">{acmeError}</div>
        {/if}

        <p>Create the following DNS TXT record, then click confirm:</p>

        <div class="form-group">
          <label>TXT Record Name</label>
          <div class="copyable-field">
            <code class="copyable-value">{manualTxtName}</code>
            <button class="btn btn-small" onclick={() => copyToClipboard(manualTxtName, 'name')}>
              {manualCopied === 'name' ? 'Copied' : 'Copy'}
            </button>
          </div>
        </div>

        <div class="form-group">
          <label>TXT Record Value</label>
          <div class="copyable-field">
            <code class="copyable-value">{manualTxtValue}</code>
            <button class="btn btn-small" onclick={() => copyToClipboard(manualTxtValue, 'value')}>
              {manualCopied === 'value' ? 'Copied' : 'Copy'}
            </button>
          </div>
        </div>

        <span class="hint">After creating the record, wait a minute or two for DNS propagation before confirming. The challenge expires after 10 minutes.</span>

        <div class="form-actions">
          <button class="btn btn-cancel" onclick={() => { manualStep = 1; manualTxtName = ''; manualTxtValue = ''; }}>Back</button>
          <button class="btn btn-primary" onclick={handleManualDnsConfirm} disabled={acmeSubmitting}>
            {acmeSubmitting ? 'Verifying...' : 'I have created the record - Confirm'}
          </button>
        </div>
      {:else}
        {#if acmeError}
          <div class="form-error">{acmeError}</div>
        {/if}

        <div class="form-group">
          <label>Domain <span class="required">*</span></label>
          <input type="text" bind:value={acmeDomain} placeholder="example.com" />
        </div>

        <div class="form-group">
          <label>Contact Email</label>
          <input type="text" bind:value={acmeEmail} placeholder="admin@example.com" />
        </div>

        <div class="form-group">
          <label>Challenge Method</label>
          <div class="radio-group">
            <label class="radio-item">
              <input type="radio" bind:group={acmeMode} value="http01" />
              HTTP-01 (port 80 must be reachable)
            </label>
            <label class="radio-item">
              <input type="radio" bind:group={acmeMode} value="dns01" />
              DNS-01 Automatic (Cloudflare or Route53)
            </label>
            <label class="radio-item">
              <input type="radio" bind:group={acmeMode} value="dns01-manual" />
              DNS-01 Manual (any provider)
            </label>
          </div>
        </div>

        {#if acmeMode === 'dns01'}
          <div class="form-group">
            <label>DNS Provider</label>
            <select bind:value={acmeDnsProvider}>
              <option value="cloudflare">Cloudflare</option>
              <option value="route53">AWS Route53</option>
            </select>
          </div>
          <div class="form-group">
            <label>Zone ID <span class="required">*</span></label>
            <input type="text" bind:value={acmeDnsZoneId} placeholder="Zone identifier" />
          </div>
          <div class="form-group">
            <label>API Token <span class="required">*</span></label>
            <input type="password" bind:value={acmeDnsApiToken} placeholder="API token" />
          </div>
          {#if acmeDnsProvider === 'route53'}
            <div class="form-group">
              <label>AWS Secret Access Key</label>
              <input type="password" bind:value={acmeDnsApiSecret} placeholder="Secret key" />
            </div>
          {/if}
          <span class="hint">Automated DNS-01 via Cloudflare or AWS Route53 API.</span>
        {/if}

        {#if acmeMode === 'dns01-manual'}
          <span class="hint">You will be given a TXT record to create manually at your DNS provider. Works with any DNS provider. The challenge expires after 10 minutes.</span>
        {/if}

        <div class="form-group">
          <label class="checkbox-item">
            <input type="checkbox" bind:checked={acmeStaging} />
            Use staging environment (for testing)
          </label>
          <span class="hint">Staging uses Let's Encrypt test servers - certificates won't be trusted by browsers but there are no rate limits. Disable for production certificates (rate limited to 50 per week per domain).</span>
        </div>

        <div class="form-actions">
          <button class="btn btn-cancel" onclick={() => (showAcmeForm = false)}>Cancel</button>
          <button class="btn btn-primary" onclick={handleAcmeProvision} disabled={acmeSubmitting}>
            {#if acmeMode === 'dns01-manual'}
              {acmeSubmitting ? 'Requesting...' : 'Get TXT Record'}
            {:else}
              {acmeSubmitting ? 'Provisioning...' : 'Provision Certificate'}
            {/if}
          </button>
        </div>
      {/if}
    </div>
  </div>
{/if}

<script lang="ts" module>
  const eyeIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
  const editIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>';
  const trashIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>';
  const gearIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>';
</script>

<style>
  .certs-page {
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
    align-items: center;
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

  .domain {
    font-weight: 600;
    color: var(--color-text-heading);
  }

  .link-btn {
    background: none;
    border: none;
    color: var(--color-primary);
    font-weight: 600;
    font-size: 0.875rem;
    padding: 0;
    text-decoration: none;
  }

  .link-btn:hover {
    text-decoration: underline;
  }

  .san-count {
    margin-left: 0.5rem;
    font-size: 0.7rem;
    font-weight: 400;
    color: var(--color-text-muted);
    background: rgba(148, 163, 184, 0.1);
    padding: 0.1rem 0.4rem;
    border-radius: 9999px;
  }

  .issuer {
    color: var(--color-text-muted);
  }

  .text-muted {
    color: var(--color-text-muted);
  }

  .mono {
    font-family: var(--mono);
    font-size: 0.75rem;
    word-break: break-all;
  }

  .route-count {
    color: var(--color-text);
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
    max-width: 520px;
    max-height: 90vh;
    overflow-y: auto;
  }

  .modal-wide {
    max-width: 680px;
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

  .form-group label {
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
  .form-group input[type="number"],
  .form-group textarea {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
    font-family: var(--sans);
  }

  .form-group textarea {
    font-family: var(--mono);
    font-size: 0.8125rem;
    resize: vertical;
  }

  .form-group input:focus,
  .form-group textarea:focus {
    outline: none;
    border-color: var(--color-primary);
  }

  .file-input-row {
    margin-bottom: 0.375rem;
  }

  .file-input-row input[type="file"] {
    font-size: 0.8125rem;
    color: var(--color-text-muted);
  }

  .field-hint {
    display: block;
    font-size: 0.75rem;
    color: var(--color-text-muted);
    margin-top: 0.25rem;
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

  .btn-secondary {
    background: var(--color-bg-input);
    color: var(--color-text);
  }

  .btn-secondary:hover {
    background: var(--color-bg-hover);
  }

  .btn-cancel {
    background: var(--color-bg-input);
    color: var(--color-text);
  }

  .btn-cancel:hover {
    background: var(--color-bg-hover);
  }

  /* Detail view */
  .detail-grid {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    margin-bottom: 1.25rem;
  }

  .detail-row {
    display: flex;
    gap: 1rem;
    align-items: baseline;
    font-size: 0.875rem;
  }

  .detail-label {
    flex: 0 0 160px;
    color: var(--color-text-muted);
    font-size: 0.8125rem;
    font-weight: 500;
  }

  .detail-value {
    color: var(--color-text);
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .detail-section {
    margin-bottom: 1.25rem;
  }

  .detail-section h3 {
    margin-bottom: 0.5rem;
  }

  .route-list {
    list-style: none;
    padding: 0;
    margin: 0;
  }

  .route-list li {
    padding: 0.375rem 0;
    font-size: 0.875rem;
    color: var(--color-text);
    border-bottom: 1px solid var(--color-border);
  }

  .route-list li:last-child {
    border-bottom: none;
  }

  .pem-block {
    background: var(--color-bg-input);
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    padding: 0.75rem;
    font-family: var(--mono);
    font-size: 0.75rem;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 200px;
    overflow-y: auto;
    color: var(--color-text-muted);
    margin: 0;
  }

  /* Self-signed preference prompt */
  .pref-text {
    color: var(--color-text-muted);
    font-size: 0.875rem;
    line-height: 1.5;
    margin: 0 0 1.25rem;
  }

  .pref-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.75rem;
  }

  .btn-acme {
    padding: 0.5rem 1rem;
    border-radius: var(--radius-md);
    font-weight: 500;
    border: 1px solid var(--color-green);
    background: var(--color-green-subtle);
    color: var(--color-green);
    font-size: var(--text-md);
    cursor: pointer;
    transition: background-color var(--transition-fast);
  }
  .btn-acme:hover {
    background: rgba(34, 197, 94, 0.2);
  }

  .success-banner {
    background: var(--color-green-subtle);
    border: 1px solid var(--color-green);
    border-radius: var(--radius-md);
    color: var(--color-green);
    padding: var(--space-3) var(--space-4);
    margin-bottom: var(--space-4);
    font-size: var(--text-base);
  }

  .radio-group {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .radio-item {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-size: var(--text-base);
    cursor: pointer;
  }

  .radio-item input[type="radio"] {
    accent-color: var(--color-primary);
  }

  .copyable-field {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .copyable-value {
    flex: 1;
    background: var(--color-bg-input);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    padding: 0.5rem 0.75rem;
    font-family: var(--mono);
    font-size: 0.8125rem;
    word-break: break-all;
    color: var(--color-text);
  }

  .btn-small {
    padding: 0.25rem 0.625rem;
    font-size: 0.75rem;
    border-radius: var(--radius-md);
    border: 1px solid var(--color-border);
    background: var(--color-bg-input);
    color: var(--color-text);
    cursor: pointer;
    white-space: nowrap;
    transition: background-color var(--transition-fast);
  }

  .btn-small:hover {
    background: var(--color-bg-hover);
  }
</style>
