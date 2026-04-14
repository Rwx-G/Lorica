<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    type CertificateResponse,
    type CertificateDetailResponse,
    type RouteResponse,
    type DnsProviderResponse,
  } from '../lib/api';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import CertificateAcmeForm from '../components/certificates/CertificateAcmeForm.svelte';
  import CertificateEditForm from '../components/certificates/CertificateEditForm.svelte';
  import CertificateList from '../components/certificates/CertificateList.svelte';
  import CertificateUploadForm from '../components/certificates/CertificateUploadForm.svelte';
  import CertificateDetail from '../components/certificates/CertificateDetail.svelte';
  import CertificateSelfSignedForm from '../components/certificates/CertificateSelfSignedForm.svelte';
  import CertificateSelfSignedPrefPrompt from '../components/certificates/CertificateSelfSignedPrefPrompt.svelte';
  import CertificateThresholdsForm from '../components/certificates/CertificateThresholdsForm.svelte';
  import { showToast } from '../lib/toast';

  let certificates: CertificateResponse[] = $state([]);
  let routes: RouteResponse[] = $state([]);
  let dnsProviders: DnsProviderResponse[] = $state([]);
  let error = $state('');
  let loading = $state(true);

  // Threshold configuration
  let warningDays = $state(30);
  let criticalDays = $state(7);
  let showThresholdConfig = $state(false);

  // Upload form state
  let showUploadForm = $state(false);

  // Edit form state
  let editingCert: CertificateResponse | null = $state(null);
  let showEditForm = $state(false);

  // Detail view state
  let detailCert: CertificateDetailResponse | null = $state(null);
  let showDetail = $state(false);
  let detailLoading = $state(false);

  // Delete state
  let deletingCert: CertificateResponse | null = $state(null);
  let deleteRoutes: RouteResponse[] = $state([]);

  // Renew state
  let renewingId = $state('');

  // Self-signed generation state
  let showSelfSigned = $state(false);
  const SS_PREF_KEY = 'lorica_self_signed_pref';
  let selfSignedPref: 'never' | 'always' | 'once' | null = $state(
    (() => {
      const v = localStorage.getItem(SS_PREF_KEY);
      return v === 'never' || v === 'always' || v === 'once' ? v : null;
    })()
  );
  let showSelfSignedPrefPrompt = $state(false);
  let showSelfSignedConfirm = $state(false);

  // ACME provisioning state
  let showAcmeForm = $state(false);

  function openAcmeForm() {
    showAcmeForm = true;
  }

  async function loadData() {
    loading = true;
    error = '';
    const [certsRes, routesRes, settingsRes, , dnsRes] = await Promise.all([
      api.listCertificates(),
      api.listRoutes(),
      api.getSettings(),
      api.listPreferences(),
      api.listDnsProviders(),
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
    if (dnsRes.data) {
      dnsProviders = dnsRes.data.dns_providers;
    }
    loading = false;
  }

  onMount(loadData);

  function getRoutesForCert(certId: string): RouteResponse[] {
    return routes.filter((r) => r.certificate_id === certId);
  }

  function openEditForm(cert: CertificateResponse) {
    editingCert = cert;
    showEditForm = true;
  }

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

  function openDelete(cert: CertificateResponse) {
    deletingCert = cert;
    deleteRoutes = getRoutesForCert(cert.id);
  }

  async function handleDelete() {
    if (!deletingCert) return;
    const res = await api.deleteCertificate(deletingCert.id);
    if (res.error) {
      showToast(res.error.message, 'error');
    } else {
      showToast('Certificate deleted', 'success');
    }
    deletingCert = null;
    deleteRoutes = [];
    await loadData();
  }

  async function handleRenew(cert: CertificateResponse) {
    renewingId = cert.id;
    const res = await api.renewCertificate(cert.id);
    if (res.error) {
      showToast(res.error.message, 'error');
    } else {
      showToast(`Certificate for ${cert.domain} renewed successfully`, 'success');
    }
    renewingId = '';
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
    if (selfSignedPref === 'once') {
      showSelfSignedConfirm = true;
      return;
    }
    showSelfSigned = true;
  }

  function confirmSelfSigned() {
    showSelfSignedConfirm = false;
    showSelfSigned = true;
  }

  async function handleSelfSignedPref(choice: 'never' | 'always' | 'once') {
    selfSignedPref = choice;
    showSelfSignedPrefPrompt = false;
    localStorage.setItem(SS_PREF_KEY, choice);
    if (choice === 'never') return;
    showSelfSigned = true;
  }

  async function onSelfSignedReloaded() {
    if (selfSignedPref === 'once') {
      selfSignedPref = null;
    }
    await loadData();
  }

  function onThresholdsSaved(warning: number, critical: number) {
    warningDays = warning;
    criticalDays = critical;
  }
</script>

<div class="certs-page">
  <div class="page-header">
    <h1>Certificates</h1>
    <div class="header-actions">
      <button class="btn btn-secondary" onclick={() => showThresholdConfig = true} title="Configure expiration thresholds">
        <!-- eslint-disable-next-line svelte/no-at-html-tags -->
        {@html gearIcon}
      </button>
      <button class="btn btn-secondary" onclick={openSelfSigned}>Self-signed</button>
      <button class="btn btn-acme" onclick={openAcmeForm}>Let's Encrypt</button>
      <button class="btn btn-primary" onclick={() => showUploadForm = true}>+ Upload Certificate</button>
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
      <p class="text-muted">You can upload a PEM certificate, generate a self-signed certificate for testing, or provision a free Let's Encrypt certificate.</p>
      <button class="btn btn-primary" onclick={() => showUploadForm = true}>Upload your first certificate</button>
    </div>
  {:else}
    <CertificateList
      {certificates}
      {routes}
      {warningDays}
      {criticalDays}
      {renewingId}
      onView={openDetail}
      onEdit={openEditForm}
      onRenew={handleRenew}
      onDelete={openDelete}
    />
  {/if}
</div>

{#if showUploadForm}
  <CertificateUploadForm onClose={() => showUploadForm = false} onReload={loadData} />
{/if}

{#if showEditForm && editingCert}
  <CertificateEditForm
    {editingCert}
    {dnsProviders}
    onClose={() => { showEditForm = false; editingCert = null; }}
    onReload={loadData}
  />
{/if}

{#if showDetail}
  <CertificateDetail
    {detailCert}
    {detailLoading}
    {routes}
    {warningDays}
    {criticalDays}
    onClose={() => { showDetail = false; detailCert = null; }}
  />
{/if}

{#if deletingCert}
  <ConfirmDialog
    title="Delete Certificate"
    message={deleteMessage()}
    onconfirm={handleDelete}
    oncancel={() => { deletingCert = null; deleteRoutes = []; }}
  />
{/if}

{#if showSelfSignedPrefPrompt}
  <CertificateSelfSignedPrefPrompt
    onChoice={handleSelfSignedPref}
    onDismiss={() => showSelfSignedPrefPrompt = false}
  />
{/if}

{#if showSelfSignedConfirm}
  <ConfirmDialog
    title="Generate Self-signed Certificate"
    message="Self-signed certificates should only be used for development and testing. Continue?"
    confirmLabel="Continue"
    confirmStyle="primary"
    onconfirm={confirmSelfSigned}
    oncancel={() => showSelfSignedConfirm = false}
  />
{/if}

{#if showSelfSigned}
  <CertificateSelfSignedForm
    onClose={() => showSelfSigned = false}
    onReload={onSelfSignedReloaded}
  />
{/if}

{#if showThresholdConfig}
  <CertificateThresholdsForm
    {warningDays}
    {criticalDays}
    onClose={() => showThresholdConfig = false}
    onSaved={onThresholdsSaved}
  />
{/if}

{#if showAcmeForm}
  <CertificateAcmeForm {dnsProviders} onClose={() => showAcmeForm = false} onReload={loadData} />
{/if}

<script lang="ts" module>
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

  .text-muted {
    color: var(--color-text-muted);
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

  .btn-secondary {
    background: var(--color-bg-input);
    color: var(--color-text);
  }

  .btn-secondary:hover {
    background: var(--color-bg-hover);
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
    opacity: 0.85;
  }
</style>
