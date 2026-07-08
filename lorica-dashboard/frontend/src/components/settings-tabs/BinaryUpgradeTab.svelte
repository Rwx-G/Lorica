<script lang="ts">
  // SuperAdmin-only once Story 8.3 RBAC lands; today it is gated by
  // the single-admin session like every other settings panel.
  import { onMount } from 'svelte';
  import {
    api,
    isValidUpgradeSignatureHex,
    type ProxyInfo,
    type UpgradeStageResult,
  } from '../../lib/api';
  import { formatBytes } from '../../lib/format';
  import ConfirmDialog from '../ConfirmDialog.svelte';

  interface Props {
    expanded: boolean;
    toggleSection: () => void;
  }

  let { expanded, toggleSection }: Props = $props();

  let proxy: ProxyInfo | null = $state(null);
  let proxyError = $state('');

  type SignatureMode = 'file' | 'paste';
  let signatureMode: SignatureMode = $state('file');
  let binaryFile: File | null = $state(null);
  let signatureFile: File | null = $state(null);
  let signatureHex = $state('');

  let uploading = $state(false);
  let confirming = $state(false);
  let result: UpgradeStageResult | null = $state(null);
  let uploadError = $state('');
  let noSigningKey = $state(false);

  async function loadProxy() {
    const res = await api.getSystem();
    if (res.error) {
      proxyError = res.error.message;
    } else if (res.data) {
      proxy = res.data.proxy;
      proxyError = '';
    }
  }

  onMount(loadProxy);

  function onBinaryChange(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    binaryFile = input.files?.[0] ?? null;
  }

  function onSignatureFileChange(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    signatureFile = input.files?.[0] ?? null;
  }

  let signatureReady = $derived(
    signatureMode === 'file'
      ? signatureFile !== null
      : isValidUpgradeSignatureHex(signatureHex),
  );

  let canSubmit = $derived(binaryFile !== null && signatureReady && !uploading);

  function requestUpgrade() {
    if (!canSubmit) return;
    confirming = true;
  }

  async function confirmUpgrade() {
    confirming = false;
    if (binaryFile === null) return;
    uploading = true;
    result = null;
    uploadError = '';
    noSigningKey = false;

    const signature: File | string =
      signatureMode === 'file' ? signatureFile! : signatureHex.trim();
    const res = await api.uploadUpgradeBinary(binaryFile, signature);

    if (res.error) {
      uploadError = res.error.message;
      noSigningKey = res.error.message
        .toLowerCase()
        .includes('no upgrade signing key configured');
    } else if (res.data) {
      result = res.data;
      // Refresh so the pid/version reflect the post-handoff process
      // once the supervisor finishes the swap.
      void loadProxy();
    }
    uploading = false;
  }

  function cancelUpgrade() {
    confirming = false;
  }
</script>

<section class="settings-section">
  <button class="settings-collapsible-header" class:open={expanded} onclick={toggleSection}>
    <h2>Binary Upgrade</h2>
    <span class="settings-chevron" class:expanded></span>
  </button>
  {#if expanded}
    <div class="settings-section-body">
      <p class="section-hint">
        Upload a new, signed <code>lorica</code> executable to upgrade in
        place with no downtime. The server verifies the detached Ed25519
        signature against the configured signing key before staging the
        binary, then hands off to the supervisor: in-flight connections
        drain over up to 30 seconds while the replacement process takes
        over the listening sockets.
      </p>

      <h3>Running version</h3>
      {#if proxyError}
        <div class="settings-form-error">{proxyError}</div>
      {:else if proxy}
        <div class="running-info">
          <div><span class="info-label">Version</span><span class="info-value">{proxy.version}</span></div>
          <div><span class="info-label">PID</span><span class="info-value">{proxy.pid}</span></div>
        </div>
      {:else}
        <p class="hint">Loading...</p>
      {/if}

      <h3>New binary</h3>
      <div class="settings-form-row">
        <label for="upgrade-binary">Binary file</label>
        <input id="upgrade-binary" type="file" onchange={onBinaryChange} />
        <span class="hint">The new <code>lorica</code> executable.</span>
      </div>

      <h3>Signature</h3>
      <div class="settings-form-row">
        <div class="mode-toggle" role="radiogroup" aria-label="Signature input mode">
          <label>
            <input type="radio" name="sig-mode" value="file" bind:group={signatureMode} />
            Upload .sig file
          </label>
          <label>
            <input type="radio" name="sig-mode" value="paste" bind:group={signatureMode} />
            Paste hex
          </label>
        </div>
      </div>

      {#if signatureMode === 'file'}
        <div class="settings-form-row">
          <label for="upgrade-signature-file">Signature file</label>
          <input id="upgrade-signature-file" type="file" accept=".sig,.txt" onchange={onSignatureFileChange} />
          <span class="hint">Detached Ed25519 signature (128 hex chars).</span>
        </div>
      {:else}
        <div class="settings-form-row">
          <label for="upgrade-signature-hex">Signature (hex)</label>
          <textarea
            id="upgrade-signature-hex"
            rows="2"
            bind:value={signatureHex}
            placeholder="128 hex characters"
            autocomplete="off"
            spellcheck="false"
          ></textarea>
          {#if signatureHex.trim() !== '' && !signatureReady}
            <span class="field-error" role="alert">
              Expected exactly 128 hex characters (64-byte Ed25519 signature).
            </span>
          {/if}
        </div>
      {/if}

      {#if uploadError}
        <div class="settings-form-error">
          {uploadError}
          {#if noSigningKey}
            <p class="key-hint">
              Set <code>upgrade_signing_pubkey_path</code> in the Lorica
              configuration to the file holding the 64-hex-char Ed25519
              verifying key, then reload, before staging an upgrade.
            </p>
          {/if}
        </div>
      {/if}

      {#if result}
        <div class="stage-success" role="status">
          <strong>Binary verified and staged.</strong>
          <div><span class="info-label">SHA-256</span><span class="info-value mono">{result.sha256}</span></div>
          <div><span class="info-label">Size</span><span class="info-value">{formatBytes(result.size, { units: 'decimal' })}</span></div>
          {#if result.handoff === 'triggered'}
            <p class="hint">
              The supervisor is draining connections and handing off to the new
              process. Refresh the running version above to confirm the PID
              changed.
            </p>
          {:else if result.handoff === 'staged_only'}
            <p class="hint">
              This instance runs in single-process mode, so no live handoff was
              performed. The binary is staged and takes effect on the next
              restart. Run Lorica with <code>--workers auto</code> (the packaged
              systemd unit does) for a true zero-downtime upgrade.
            </p>
          {:else}
            <p class="hint">
              The binary is staged, but the handoff signal could not be
              delivered (an upgrade may already be in progress). Retry once it
              settles; the staged binary is in place.
            </p>
          {/if}
        </div>
      {/if}

      <div class="settings-dialog-actions">
        <button class="btn btn-warning" onclick={requestUpgrade} disabled={!canSubmit}>
          {uploading ? 'Uploading...' : 'Verify & stage upgrade'}
        </button>
      </div>
    </div>
  {/if}
</section>

{#if confirming}
  <ConfirmDialog
    title="Start binary upgrade?"
    message="The server will verify the signature, stage the new binary, then replace this process. In-flight traffic drains over up to 30 seconds while the new process takes over. This cannot be undone from the dashboard."
    confirmLabel="Start upgrade"
    confirmStyle="warning"
    onconfirm={confirmUpgrade}
    oncancel={cancelUpgrade}
  />
{/if}

<style>
  .section-hint {
    color: var(--color-text-muted, #666);
    font-size: 0.9em;
    margin: 0 0 1rem;
  }
  .hint {
    display: block;
    font-size: 0.75rem;
    color: var(--color-text-muted);
    margin-top: 0.25rem;
  }
  h3 {
    margin: var(--space-4) 0 var(--space-2);
    font-size: var(--text-md);
    color: var(--color-text-heading);
    border-top: 1px solid var(--color-border);
    padding-top: var(--space-4);
  }
  .running-info {
    display: flex;
    gap: var(--space-6);
    flex-wrap: wrap;
  }
  .running-info > div {
    display: flex;
    flex-direction: column;
    gap: 0.125rem;
  }
  .info-label {
    font-size: 0.75rem;
    color: var(--color-text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .info-value {
    font-size: 1rem;
    font-weight: 600;
  }
  .mono {
    font-family: var(--font-mono, ui-monospace, monospace);
    font-weight: 400;
    word-break: break-all;
  }
  .mode-toggle {
    display: flex;
    gap: var(--space-4);
  }
  .mode-toggle label {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-size: var(--text-sm);
    color: var(--color-text-muted);
  }
  .field-error {
    display: block;
    color: var(--color-red);
    font-size: var(--text-xs);
    margin-top: 0.25rem;
  }
  .stage-success {
    border: 1px solid var(--color-green, #16a34a);
    border-radius: 0.5rem;
    padding: 0.75rem 1rem;
    margin-top: var(--space-3);
    display: flex;
    flex-direction: column;
    gap: 0.375rem;
  }
  .key-hint {
    margin: 0.5rem 0 0;
    font-size: 0.8125rem;
  }
</style>
