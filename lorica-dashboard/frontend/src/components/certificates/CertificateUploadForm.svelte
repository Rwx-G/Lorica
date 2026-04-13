<script lang="ts">
  import { api, type CreateCertificateRequest } from '../../lib/api';

  interface Props {
    onClose: () => void;
    onReload: () => Promise<void>;
  }

  let { onClose, onReload }: Props = $props();

  let formDomain = $state('');
  let formCertPem = $state('');
  let formKeyPem = $state('');
  let formError = $state('');
  let formSubmitting = $state(false);

  const DOMAIN_PATTERN = /^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/;

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') onClose();
  }

  async function handleFileInput(e: Event, target: 'cert' | 'key') {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    const text = await file.text();
    if (target === 'cert') formCertPem = text;
    else formKeyPem = text;
  }

  function validateForm(): string {
    if (!formDomain.trim()) return 'Domain is required';
    if (!DOMAIN_PATTERN.test(formDomain.trim())) return 'Invalid domain pattern';
    if (!formCertPem.trim()) return 'Certificate PEM is required';
    if (!formCertPem.trim().startsWith('-----BEGIN CERTIFICATE-----'))
      return 'Certificate PEM must start with -----BEGIN CERTIFICATE-----';
    if (!formKeyPem.trim()) return 'Private key PEM is required';
    if (!formKeyPem.trim().startsWith('-----BEGIN'))
      return 'Key PEM must start with -----BEGIN (RSA/EC/PRIVATE KEY)';
    return '';
  }

  async function handleSubmit() {
    const err = validateForm();
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
    onClose();
    await onReload();
  }
</script>

<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<div class="overlay" onclick={(e) => { if (e.target === e.currentTarget) onClose(); }} onkeydown={handleKeydown} role="dialog" aria-modal="true" tabindex="-1">
  <div class="modal" role="document">
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
      <button class="btn btn-cancel" onclick={onClose}>Cancel</button>
      <button class="btn btn-primary" disabled={formSubmitting} onclick={handleSubmit}>
        {formSubmitting ? 'Uploading...' : 'Upload'}
      </button>
    </div>
  </div>
</div>

<style>
  .form-error {
    background: var(--color-red-subtle);
    border: 1px solid var(--color-red);
    border-radius: var(--radius-md);
    color: var(--color-red);
    padding: var(--space-2) var(--space-3);
    font-size: var(--text-base);
    margin-bottom: var(--space-4);
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
</style>
