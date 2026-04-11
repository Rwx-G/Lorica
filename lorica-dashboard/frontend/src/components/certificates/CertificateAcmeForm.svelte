<script lang="ts">
  import {
    api,
    type AcmeProvisionRequest,
    type AcmeDnsProvisionRequest,
    type AcmeDnsManualRequest,
    type AcmeDnsManualConfirmRequest,
    type DnsManualTxtRecord,
    type DnsProviderResponse,
  } from '../../lib/api';

  let {
    dnsProviders,
    onClose,
    onReload,
  }: {
    dnsProviders: DnsProviderResponse[];
    onClose: () => void;
    onReload: () => Promise<void>;
  } = $props();

  // ACME provisioning state
  let acmeMode: 'http01' | 'dns01' | 'dns01-manual' = $state('http01');
  let acmeDomain = $state('');
  let acmeEmail = $state('');
  let acmeStaging = $state(false);
  let acmeDnsProvider = $state('cloudflare');
  let acmeDnsProviderId = $state('');
  let acmeDnsZoneId = $state('');
  let acmeDnsApiToken = $state('');
  let acmeDnsApiSecret = $state('');
  // OVH-specific fields
  let acmeOvhConsumerKey = $state('');
  let acmeOvhEndpoint = $state('eu.api.ovh.com');
  let acmeError = $state('');
  let acmeSubmitting = $state(false);
  let acmeSuccess = $state('');
  // Manual DNS-01 two-step state
  let manualTxtName = $state('');
  let manualTxtValue = $state('');
  let manualTxtRecords: DnsManualTxtRecord[] = $state([]);
  let manualPendingDomain = $state('');
  let manualStep: 1 | 2 = $state(1);
  let manualCopied = $state('');

  async function copyToClipboard(text: string, label: string) {
    try {
      await navigator.clipboard.writeText(text);
      manualCopied = label;
      setTimeout(() => { manualCopied = ''; }, 3000);
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
    if (acmeEmail.trim() && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(acmeEmail.trim())) {
      acmeError = 'Invalid email address';
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
        await onReload();
      }
    } else if (acmeMode === 'dns01') {
      // Use global DNS provider if selected, otherwise inline credentials
      if (acmeDnsProviderId) {
        const body: AcmeDnsProvisionRequest = {
          domain: acmeDomain,
          staging: acmeStaging,
          contact_email: acmeEmail || undefined,
          dns_provider_id: acmeDnsProviderId,
        };
        const res = await api.provisionAcmeDns(body);
        acmeSubmitting = false;
        if (res.error) {
          acmeError = res.error.message;
        } else if (res.data) {
          acmeSuccess = res.data.message;
          await onReload();
        }
      } else {
        // Legacy inline credentials
        if (acmeDnsProvider === 'ovh') {
          if (!acmeDnsApiToken.trim() || !acmeDnsApiSecret.trim() || !acmeOvhConsumerKey.trim()) {
            acmeError = 'Application Key, Application Secret and Consumer Key are required for OVH';
            acmeSubmitting = false;
            return;
          }
        } else {
          if (!acmeDnsZoneId.trim() || !acmeDnsApiToken.trim()) {
            acmeError = 'Zone ID and API token are required for DNS-01';
            acmeSubmitting = false;
            return;
          }
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
            ovh_endpoint: acmeDnsProvider === 'ovh' ? acmeOvhEndpoint : undefined,
            ovh_consumer_key: acmeDnsProvider === 'ovh' ? acmeOvhConsumerKey : undefined,
          },
        };
        const res = await api.provisionAcmeDns(body);
        acmeSubmitting = false;
        if (res.error) {
          acmeError = res.error.message;
        } else if (res.data) {
          acmeSuccess = res.data.message;
          await onReload();
        }
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
        manualTxtRecords = res.data.txt_records || [];
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
      manualTxtRecords = [];
      manualPendingDomain = '';
      await onReload();
    }
  }
</script>

<!-- ACME Provisioning Modal -->
<div class="overlay" role="dialog" aria-modal="true" tabindex="-1" onclick={(e) => { if (e.target === e.currentTarget) onClose(); }} onkeydown={(e) => { if (e.key === 'Escape') onClose(); }}>
  <div class="modal">
    <h2>Let's Encrypt Certificate</h2>

    {#if acmeSuccess}
      <div class="success-banner">{acmeSuccess}</div>
      <div class="form-actions">
        <button class="btn btn-primary" onclick={onClose}>Close</button>
      </div>
    {:else if acmeMode === 'dns01-manual' && manualStep === 2}
      <!-- Manual DNS-01 Step 2: show TXT record and confirm -->
      {#if acmeError}
        <div class="form-error">{acmeError}</div>
      {/if}

      <h3>Step 2 of 2 - Create DNS Record{manualTxtRecords.length > 1 ? 's' : ''}</h3>

      {#if manualTxtRecords.length <= 1}
        <p>Add this TXT record at your DNS provider for <strong>{manualPendingDomain}</strong>, then click confirm.</p>

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
      {:else}
        <p>Add the following {manualTxtRecords.length} TXT records at your DNS provider, then click confirm.</p>

        {#each manualTxtRecords as rec, i}
          <div class="form-group" style="border-left: 3px solid var(--border-color); padding-left: 12px; margin-bottom: 16px;">
            <label><strong>{rec.domain}</strong></label>
            <div style="margin-top: 4px;">
              <label>TXT Record Name</label>
              <div class="copyable-field">
                <code class="copyable-value">{rec.name}</code>
                <button class="btn btn-small" onclick={() => copyToClipboard(rec.name, `name-${i}`)}>
                  {manualCopied === `name-${i}` ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>
            <div style="margin-top: 4px;">
              <label>TXT Record Value</label>
              <div class="copyable-field">
                <code class="copyable-value">{rec.value}</code>
                <button class="btn btn-small" onclick={() => copyToClipboard(rec.value, `value-${i}`)}>
                  {manualCopied === `value-${i}` ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>
          </div>
        {/each}
      {/if}

      <span class="hint">After creating the record{manualTxtRecords.length > 1 ? 's' : ''}, wait a minute or two for DNS propagation before confirming. The challenge expires after 10 minutes.</span>

      <div class="form-actions">
        <button class="btn btn-cancel" onclick={() => { if (window.confirm('Going back will abandon the current ACME challenge. Continue?')) { manualStep = 1; manualTxtName = ''; manualTxtValue = ''; manualTxtRecords = []; } }}>Back</button>
        <button class="btn btn-primary" onclick={handleManualDnsConfirm} disabled={acmeSubmitting}>
          {acmeSubmitting ? 'Verifying...' : `I have created the record${manualTxtRecords.length > 1 ? 's' : ''} - Confirm`}
        </button>
      </div>
    {:else}
      {#if acmeError}
        <div class="form-error">{acmeError}</div>
      {/if}

      <div class="form-group">
        <label>Domain(s) <span class="required">*</span></label>
        <input type="text" bind:value={acmeDomain} placeholder="example.com, www.example.com" />
        <span class="hint">Separate multiple domains with commas for a SAN certificate. Use *.example.com for wildcards (DNS-01 only).</span>
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
            DNS-01 Automatic (Cloudflare, Route53, OVH)
          </label>
          <label class="radio-item">
            <input type="radio" bind:group={acmeMode} value="dns01-manual" />
            DNS-01 Manual (any provider)
          </label>
        </div>
      </div>

      {#if acmeMode === 'dns01'}
        {#if dnsProviders.length > 0}
          <div class="form-group">
            <label>DNS Provider</label>
            <select bind:value={acmeDnsProviderId}>
              <option value="">-- Enter credentials manually --</option>
              {#each dnsProviders as dp}
                <option value={dp.id}>{dp.name} ({dp.provider_type})</option>
              {/each}
            </select>
          </div>
        {:else}
          <p class="hint">No DNS providers configured. <a href="#/settings">Add one in Settings</a> or enter credentials below.</p>
        {/if}

        {#if !acmeDnsProviderId}
          <div class="form-group">
            <label>DNS Provider Type</label>
            <select bind:value={acmeDnsProvider}>
              <option value="cloudflare">Cloudflare</option>
              <option value="route53">AWS Route53</option>
              <option value="ovh">OVH</option>
            </select>
          </div>
          {#if acmeDnsProvider === 'ovh'}
            <div class="form-group">
              <label>Application Key <span class="required">*</span></label>
              <input type="text" bind:value={acmeDnsApiToken} placeholder="OVH Application Key" />
            </div>
            <div class="form-group">
              <label>Application Secret <span class="required">*</span></label>
              <input type="password" bind:value={acmeDnsApiSecret} placeholder="OVH Application Secret" />
            </div>
            <div class="form-group">
              <label>Consumer Key <span class="required">*</span></label>
              <input type="password" bind:value={acmeOvhConsumerKey} placeholder="OVH Consumer Key" />
            </div>
            <div class="form-group">
              <label>API Endpoint</label>
              <select bind:value={acmeOvhEndpoint}>
                <option value="eu.api.ovh.com">Europe (eu.api.ovh.com)</option>
                <option value="ca.api.ovh.com">Canada (ca.api.ovh.com)</option>
                <option value="api.us.ovhcloud.com">US (api.us.ovhcloud.com)</option>
              </select>
            </div>
          {:else}
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
          {/if}
        {/if}
        <span class="hint">Automated DNS-01 via Cloudflare, AWS Route53 or OVH API.</span>
      {/if}

      {#if acmeMode === 'dns01-manual'}
        <span class="hint">You will be given a TXT record to create manually at your DNS provider. Works with any DNS provider. The challenge expires after 10 minutes.</span>
      {/if}

      <div class="form-group" style="margin-top: var(--space-4);">
        <label class="checkbox-item">
          <input type="checkbox" bind:checked={acmeStaging} />
          Use staging environment (for testing)
        </label>
        <span class="hint">Staging uses Let's Encrypt test servers - certificates won't be trusted by browsers but there are no rate limits. Disable for production certificates (rate limited to 50 per week per domain).</span>
      </div>

      <div class="form-actions">
        <button class="btn btn-cancel" onclick={onClose}>Cancel</button>
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
