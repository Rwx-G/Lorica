<script lang="ts">
  import {
    api,
    type DnsProviderResponse,
    type DnsProviderConfig,
  } from '../../lib/api';
  import ConfirmDialog from '../ConfirmDialog.svelte';
  import { showToast } from '../../lib/toast';

  let {
    dnsProviders = $bindable([]),
    expandedSections = $bindable({}),
    toggleSection,
    onReload,
  }: {
    dnsProviders: DnsProviderResponse[];
    expandedSections: Record<string, boolean>;
    toggleSection: (key: string) => void;
    onReload: () => Promise<void>;
  } = $props();

  // DNS Provider form state
  let showDnsProviderForm = $state(false);
  let dnsProviderEditing: DnsProviderResponse | null = $state(null);
  let dnsProviderName = $state('');
  let dnsProviderType = $state('ovh');
  // OVH fields
  let dpOvhEndpoint = $state('eu.api.ovh.com');
  let dpOvhAppKey = $state('');
  let dpOvhAppSecret = $state('');
  let dpOvhConsumerKey = $state('');
  // Cloudflare fields
  let dpCfApiToken = $state('');
  let dpCfZoneId = $state('');
  // Route53 fields
  let dpR53AccessKey = $state('');
  let dpR53SecretKey = $state('');
  let dpR53HostedZoneId = $state('');
  let dnsProviderError = $state('');
  let dnsProviderSaving = $state(false);
  let deletingDnsProvider: DnsProviderResponse | null = $state(null);
  let testingDnsProvider = $state('');

  function openDnsProviderCreate() {
    dnsProviderEditing = null;
    dnsProviderName = '';
    dnsProviderType = 'ovh';
    dpOvhEndpoint = 'eu.api.ovh.com';
    dpOvhAppKey = '';
    dpOvhAppSecret = '';
    dpOvhConsumerKey = '';
    dpCfApiToken = '';
    dpCfZoneId = '';
    dpR53AccessKey = '';
    dpR53SecretKey = '';
    dpR53HostedZoneId = '';
    dnsProviderError = '';
    showDnsProviderForm = true;
  }

  function openDnsProviderEdit(p: DnsProviderResponse) {
    dnsProviderEditing = p;
    dnsProviderName = p.name;
    dnsProviderType = p.provider_type;
    // Credentials are write-only, fields start empty on edit
    dpOvhEndpoint = 'eu.api.ovh.com';
    dpOvhAppKey = '';
    dpOvhAppSecret = '';
    dpOvhConsumerKey = '';
    dpCfApiToken = '';
    dpCfZoneId = '';
    dpR53AccessKey = '';
    dpR53SecretKey = '';
    dpR53HostedZoneId = '';
    dnsProviderError = '';
    showDnsProviderForm = true;
  }

  async function saveDnsProvider() {
    dnsProviderSaving = true;
    dnsProviderError = '';

    if (!dnsProviderName.trim()) {
      dnsProviderError = 'Name is required';
      dnsProviderSaving = false;
      return;
    }

    const config: DnsProviderConfig = {};
    if (dnsProviderType === 'ovh') {
      config.ovh_endpoint = dpOvhEndpoint;
      config.ovh_application_key = dpOvhAppKey;
      config.ovh_application_secret = dpOvhAppSecret;
      config.ovh_consumer_key = dpOvhConsumerKey;
    } else if (dnsProviderType === 'cloudflare') {
      config.api_token = dpCfApiToken;
      config.zone_id = dpCfZoneId;
    } else if (dnsProviderType === 'route53') {
      config.aws_access_key_id = dpR53AccessKey;
      config.aws_secret_access_key = dpR53SecretKey;
      config.hosted_zone_id = dpR53HostedZoneId;
    }

    const body = { name: dnsProviderName.trim(), provider_type: dnsProviderType, config };

    if (dnsProviderEditing) {
      const res = await api.updateDnsProvider(dnsProviderEditing.id, body);
      if (res.error) { dnsProviderError = res.error.message; dnsProviderSaving = false; return; }
    } else {
      const res = await api.createDnsProvider(body);
      if (res.error) { dnsProviderError = res.error.message; dnsProviderSaving = false; return; }
    }
    showDnsProviderForm = false;
    dnsProviderSaving = false;
    await onReload();
  }

  async function confirmDeleteDnsProvider() {
    if (!deletingDnsProvider) return;
    const res = await api.deleteDnsProvider(deletingDnsProvider.id);
    if (res.error) {
      showToast(res.error.message, 'error');
    }
    deletingDnsProvider = null;
    await onReload();
  }

  async function handleTestDnsProvider(id: string) {
    testingDnsProvider = id;
    const res = await api.testDnsProvider(id);
    if (res.error) {
      showToast(`Test failed: ${res.error.message}`, 'error');
    } else {
      showToast(`DNS provider configuration is valid`, 'success');
    }
    testingDnsProvider = '';
  }
</script>

<!-- DNS Providers -->
<section class="settings-section">
  <button class="settings-collapsible-header" class:open={expandedSections.dns_providers} onclick={() => toggleSection('dns_providers')}>
    <h2>DNS Providers</h2>
    <span class="settings-chevron" class:expanded={expandedSections.dns_providers}></span>
  </button>
  {#if expandedSections.dns_providers}
    <div class="settings-section-body">
      <p class="settings-hint">Global DNS provider credentials for ACME DNS-01 certificate provisioning. Credentials are stored encrypted and never shown back.</p>

      {#if dnsProviders.length === 0}
        <p class="empty-text">No DNS providers configured.</p>
      {:else}
        <div class="table-wrap">
          <table class="settings-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each dnsProviders as dp}
                <tr>
                  <td>{dp.name}</td>
                  <td class="capitalize">{dp.provider_type}</td>
                  <td class="mono">{new Date(dp.created_at).toLocaleDateString()}</td>
                  <td class="actions-cell">
                    <button class="settings-btn-action settings-btn-test" onclick={() => handleTestDnsProvider(dp.id)} disabled={testingDnsProvider === dp.id}>
                      {testingDnsProvider === dp.id ? 'Testing...' : 'Test'}
                    </button>
                    <button class="settings-btn-action settings-btn-edit" onclick={() => openDnsProviderEdit(dp)}>Edit</button>
                    <button class="settings-btn-action settings-btn-delete" onclick={() => deletingDnsProvider = dp}>Delete</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
      <div class="settings-actions-left">
        <button class="btn btn-primary" onclick={openDnsProviderCreate}>Add Provider</button>
      </div>
    </div>
  {/if}
</section>

<!-- DNS Provider form modal -->
{#if showDnsProviderForm}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="settings-overlay" onclick={(e) => { if (e.target === e.currentTarget) showDnsProviderForm = false; }} onkeydown={(e) => { if (e.key === 'Escape') showDnsProviderForm = false; }} role="dialog" aria-modal="true" tabindex="-1">
    <div class="settings-dialog" role="document">
      <h3>{dnsProviderEditing ? 'Edit' : 'Add'} DNS Provider</h3>

      <div class="settings-form-row">
        <label for="dp-name">Name <span class="settings-required">*</span></label>
        <input id="dp-name" type="text" bind:value={dnsProviderName} placeholder="e.g. OVH example.com" />
      </div>

      <div class="settings-form-row">
        <label for="dp-type">Provider Type</label>
        <select id="dp-type" bind:value={dnsProviderType}>
          <option value="ovh">OVH</option>
          <option value="cloudflare">Cloudflare</option>
          <option value="route53">AWS Route53</option>
        </select>
      </div>

      {#if dnsProviderType === 'ovh'}
        <div class="settings-form-row">
          <label for="dp-ovh-appkey">Application Key <span class="settings-required">*</span></label>
          <input id="dp-ovh-appkey" type="text" bind:value={dpOvhAppKey} placeholder="OVH Application Key" />
        </div>
        <div class="settings-form-row">
          <label for="dp-ovh-appsecret">Application Secret <span class="settings-required">*</span></label>
          <input id="dp-ovh-appsecret" type="password" bind:value={dpOvhAppSecret} placeholder="OVH Application Secret" />
        </div>
        <div class="settings-form-row">
          <label for="dp-ovh-ck">Consumer Key <span class="settings-required">*</span></label>
          <input id="dp-ovh-ck" type="password" bind:value={dpOvhConsumerKey} placeholder="OVH Consumer Key" />
        </div>
        <div class="settings-form-row">
          <label for="dp-ovh-endpoint">API Endpoint</label>
          <select id="dp-ovh-endpoint" bind:value={dpOvhEndpoint}>
            <option value="eu.api.ovh.com">Europe (eu.api.ovh.com)</option>
            <option value="ca.api.ovh.com">Canada (ca.api.ovh.com)</option>
            <option value="api.us.ovhcloud.com">US (api.us.ovhcloud.com)</option>
          </select>
        </div>
      {:else if dnsProviderType === 'cloudflare'}
        <div class="settings-form-row">
          <label for="dp-cf-token">API Token <span class="settings-required">*</span></label>
          <input id="dp-cf-token" type="password" bind:value={dpCfApiToken} placeholder="Cloudflare API token" />
        </div>
        <div class="settings-form-row">
          <label for="dp-cf-zone">Zone ID <span class="settings-required">*</span></label>
          <input id="dp-cf-zone" type="text" bind:value={dpCfZoneId} placeholder="Zone identifier" />
        </div>
      {:else if dnsProviderType === 'route53'}
        <div class="settings-form-row">
          <label for="dp-r53-key">AWS Access Key ID <span class="settings-required">*</span></label>
          <input id="dp-r53-key" type="text" bind:value={dpR53AccessKey} placeholder="Access key ID" />
        </div>
        <div class="settings-form-row">
          <label for="dp-r53-secret">AWS Secret Access Key <span class="settings-required">*</span></label>
          <input id="dp-r53-secret" type="password" bind:value={dpR53SecretKey} placeholder="Secret access key" />
        </div>
        <div class="settings-form-row">
          <label for="dp-r53-zone">Hosted Zone ID <span class="settings-required">*</span></label>
          <input id="dp-r53-zone" type="text" bind:value={dpR53HostedZoneId} placeholder="Hosted zone ID" />
        </div>
      {/if}

      {#if dnsProviderEditing}
        <p class="settings-hint">Credentials are write-only. Fill in all required fields to update them.</p>
      {/if}

      {#if dnsProviderError}
        <p class="settings-form-error">{dnsProviderError}</p>
      {/if}

      <div class="settings-dialog-actions">
        <button class="btn btn-cancel" onclick={() => showDnsProviderForm = false}>Cancel</button>
        <button class="btn btn-primary" onclick={saveDnsProvider} disabled={dnsProviderSaving}>
          {dnsProviderSaving ? 'Saving...' : (dnsProviderEditing ? 'Update' : 'Create')}
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- Delete DNS provider confirm -->
{#if deletingDnsProvider}
  <ConfirmDialog
    title="Delete DNS Provider"
    message="Are you sure you want to delete the DNS provider '{deletingDnsProvider.name}'?"
    onconfirm={confirmDeleteDnsProvider}
    oncancel={() => deletingDnsProvider = null}
  />
{/if}

