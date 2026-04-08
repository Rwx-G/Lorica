<script lang="ts">
  import {
    api,
    type CertificateResponse,
    type UpdateCertificateRequest,
    type DnsProviderResponse,
  } from '../../lib/api';

  let {
    editingCert,
    dnsProviders,
    onClose,
    onReload,
  }: {
    editingCert: CertificateResponse;
    dnsProviders: DnsProviderResponse[];
    onClose: () => void;
    onReload: () => Promise<void>;
  } = $props();

  const DOMAIN_PATTERN = /^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/;

  // Edit form state
  let editDomain = $state(editingCert.domain);
  let editCertPem = $state('');
  let editKeyPem = $state('');
  let editError = $state('');
  let editSubmitting = $state(false);
  let editDnsProviderId = $state(editingCert.acme_dns_provider_id ?? '');
  let editAcmeMethod = $state(editingCert.acme_method ?? '');
  let editAutoRenew = $state(editingCert.acme_auto_renew);

  function handleEditKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') onClose();
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
    if (editingCert.is_acme) {
      const origMethod = editingCert.acme_method ?? '';
      if (editAcmeMethod !== origMethod) body.acme_method = editAcmeMethod || undefined;
      if (editDnsProviderId !== (editingCert.acme_dns_provider_id ?? '')) body.acme_dns_provider_id = editDnsProviderId || '';
      if (editAutoRenew !== editingCert.acme_auto_renew) body.acme_auto_renew = editAutoRenew;
    }

    if (Object.keys(body).length === 0) {
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
    onClose();
    await onReload();
  }
</script>

<!-- Edit Form Modal -->
<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<div class="overlay" onclick={(e) => { if (e.target === e.currentTarget) onClose(); }} onkeydown={handleEditKeydown} role="dialog" aria-modal="true" tabindex="-1">
  <div class="modal" role="document">
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

    {#if editingCert?.is_acme}
      <div class="form-group">
        <label for="edit-acme-method">ACME Method</label>
        <select id="edit-acme-method" bind:value={editAcmeMethod}>
          <option value="http01">HTTP-01</option>
          <option value="dns01-ovh">DNS-01 (OVH)</option>
          <option value="dns01-cloudflare">DNS-01 (Cloudflare)</option>
          <option value="dns01-route53">DNS-01 (Route53)</option>
          <option value="dns01-manual">DNS-01 (Manual)</option>
        </select>
      </div>

      {#if editAcmeMethod.startsWith('dns01-') && editAcmeMethod !== 'dns01-manual'}
        <div class="form-group">
          <label for="edit-dns-provider">DNS Provider</label>
          <select id="edit-dns-provider" bind:value={editDnsProviderId}>
            <option value="">-- Select provider --</option>
            {#each dnsProviders as p}
              <option value={p.id}>{p.name} ({p.provider_type})</option>
            {/each}
          </select>
          <span class="hint">Select the DNS provider for auto-renewal. Configure providers in Settings.</span>
        </div>
      {/if}

      <div class="form-group">
        <label>
          <input type="checkbox" bind:checked={editAutoRenew} />
          Auto-renew
        </label>
      </div>
    {/if}

    <div class="form-actions">
      <button class="btn btn-cancel" onclick={onClose}>Cancel</button>
      <button class="btn btn-primary" disabled={editSubmitting} onclick={handleEditSubmit}>
        {editSubmitting ? 'Saving...' : 'Update'}
      </button>
    </div>
  </div>
</div>
