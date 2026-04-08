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
<section class="section">
  <button class="collapsible-header" class:open={expandedSections.dns_providers} onclick={() => toggleSection('dns_providers')}>
    <h2>DNS Providers</h2>
    <span class="chevron" class:expanded={expandedSections.dns_providers}></span>
  </button>
  {#if expandedSections.dns_providers}
    <div class="section-body">
      <p class="section-hint">Global DNS provider credentials for ACME DNS-01 certificate provisioning. Credentials are stored encrypted and never shown back.</p>

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
                    <button class="btn-table-action btn-table-test" onclick={() => handleTestDnsProvider(dp.id)} disabled={testingDnsProvider === dp.id}>
                      {testingDnsProvider === dp.id ? 'Testing...' : 'Test'}
                    </button>
                    <button class="btn-table-action btn-table-edit" onclick={() => openDnsProviderEdit(dp)}>Edit</button>
                    <button class="btn-table-action btn-table-delete" onclick={() => deletingDnsProvider = dp}>Delete</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
      <div class="actions-left">
        <button class="btn btn-primary" onclick={openDnsProviderCreate}>Add Provider</button>
      </div>
    </div>
  {/if}
</section>

<!-- DNS Provider form modal -->
{#if showDnsProviderForm}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="overlay" onclick={(e) => { if (e.target === e.currentTarget) showDnsProviderForm = false; }} onkeydown={(e) => { if (e.key === 'Escape') showDnsProviderForm = false; }} role="dialog" aria-modal="true" tabindex="-1">
    <div class="dialog" role="document">
      <h3>{dnsProviderEditing ? 'Edit' : 'Add'} DNS Provider</h3>

      <div class="form-row">
        <label for="dp-name">Name <span class="required">*</span></label>
        <input id="dp-name" type="text" bind:value={dnsProviderName} placeholder="e.g. OVH example.com" />
      </div>

      <div class="form-row">
        <label for="dp-type">Provider Type</label>
        <select id="dp-type" bind:value={dnsProviderType}>
          <option value="ovh">OVH</option>
          <option value="cloudflare">Cloudflare</option>
          <option value="route53">AWS Route53</option>
        </select>
      </div>

      {#if dnsProviderType === 'ovh'}
        <div class="form-row">
          <label for="dp-ovh-appkey">Application Key <span class="required">*</span></label>
          <input id="dp-ovh-appkey" type="text" bind:value={dpOvhAppKey} placeholder="OVH Application Key" />
        </div>
        <div class="form-row">
          <label for="dp-ovh-appsecret">Application Secret <span class="required">*</span></label>
          <input id="dp-ovh-appsecret" type="password" bind:value={dpOvhAppSecret} placeholder="OVH Application Secret" />
        </div>
        <div class="form-row">
          <label for="dp-ovh-ck">Consumer Key <span class="required">*</span></label>
          <input id="dp-ovh-ck" type="password" bind:value={dpOvhConsumerKey} placeholder="OVH Consumer Key" />
        </div>
        <div class="form-row">
          <label for="dp-ovh-endpoint">API Endpoint</label>
          <select id="dp-ovh-endpoint" bind:value={dpOvhEndpoint}>
            <option value="eu.api.ovh.com">Europe (eu.api.ovh.com)</option>
            <option value="ca.api.ovh.com">Canada (ca.api.ovh.com)</option>
            <option value="api.us.ovhcloud.com">US (api.us.ovhcloud.com)</option>
          </select>
        </div>
      {:else if dnsProviderType === 'cloudflare'}
        <div class="form-row">
          <label for="dp-cf-token">API Token <span class="required">*</span></label>
          <input id="dp-cf-token" type="password" bind:value={dpCfApiToken} placeholder="Cloudflare API token" />
        </div>
        <div class="form-row">
          <label for="dp-cf-zone">Zone ID <span class="required">*</span></label>
          <input id="dp-cf-zone" type="text" bind:value={dpCfZoneId} placeholder="Zone identifier" />
        </div>
      {:else if dnsProviderType === 'route53'}
        <div class="form-row">
          <label for="dp-r53-key">AWS Access Key ID <span class="required">*</span></label>
          <input id="dp-r53-key" type="text" bind:value={dpR53AccessKey} placeholder="Access key ID" />
        </div>
        <div class="form-row">
          <label for="dp-r53-secret">AWS Secret Access Key <span class="required">*</span></label>
          <input id="dp-r53-secret" type="password" bind:value={dpR53SecretKey} placeholder="Secret access key" />
        </div>
        <div class="form-row">
          <label for="dp-r53-zone">Hosted Zone ID <span class="required">*</span></label>
          <input id="dp-r53-zone" type="text" bind:value={dpR53HostedZoneId} placeholder="Hosted zone ID" />
        </div>
      {/if}

      {#if dnsProviderEditing}
        <p class="section-hint">Credentials are write-only. Fill in all required fields to update them.</p>
      {/if}

      {#if dnsProviderError}
        <p class="form-error">{dnsProviderError}</p>
      {/if}

      <div class="form-actions">
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

<style>
  .collapsible-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    width: 100%;
    padding: var(--space-3) var(--space-4);
    background: var(--color-bg-input);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    cursor: pointer;
    transition: background-color var(--transition-fast);
    font-family: inherit;
  }
  .collapsible-header:hover { background: var(--color-bg-hover); }
  .collapsible-header.open { border-radius: var(--radius-md) var(--radius-md) 0 0; border-bottom-color: transparent; }
  .collapsible-header h2 { margin: 0; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; color: var(--color-text-heading); }
  .chevron { display: inline-block; width: 0.5rem; height: 0.5rem; border-right: 2px solid var(--color-text-muted); border-bottom: 2px solid var(--color-text-muted); transform: rotate(45deg); transition: transform 0.2s ease; flex-shrink: 0; }
  .chevron.expanded { transform: rotate(-135deg); }
  .section-body { background: var(--color-bg-card); border: 1px solid var(--color-border); border-top: none; border-radius: 0 0 var(--radius-md) var(--radius-md); padding: var(--space-4); }
  .section-hint { color: var(--color-text-muted); font-size: 0.8125rem; margin: 0.25rem 0 1rem; }
  .settings-table { width: 100%; table-layout: fixed; border-collapse: collapse; }
  .settings-table th { text-align: left; font-size: var(--text-xs); text-transform: uppercase; color: var(--color-text-muted); padding: var(--space-2) var(--space-3); border-bottom: 1px solid var(--color-border); }
  .settings-table th:nth-child(1) { width: 25%; }
  .settings-table th:nth-child(2) { width: 20%; }
  .settings-table th:nth-child(3) { width: 25%; }
  .settings-table th:nth-child(4) { width: 30%; }
  .settings-table td { padding: var(--space-2) var(--space-3); border-bottom: 1px solid var(--color-border); font-size: var(--text-sm); vertical-align: middle; }
  .btn-table-action { padding: 0.25rem 0.5rem; border-radius: var(--radius-sm); font-size: var(--text-xs); font-weight: 500; border: 1px solid; background: transparent; cursor: pointer; transition: all 0.15s; }
  .btn-table-edit { color: var(--color-primary); border-color: var(--color-primary); }
  .btn-table-edit:hover { background: var(--color-primary-subtle); }
  .btn-table-delete { color: var(--color-red); border-color: var(--color-red); }
  .btn-table-delete:hover { background: var(--color-red-subtle); }
  .btn-table-test { color: var(--color-green); border-color: var(--color-green); }
  .btn-table-test:hover { background: var(--color-green-subtle); }
  .actions-left { display: flex; justify-content: flex-start; margin-top: var(--space-3); }
  .form-card { background: var(--color-bg-card); border: 1px solid var(--color-border); border-radius: 0.75rem; padding: 1.25rem; }
  .form-row { display: flex; flex-direction: column; gap: var(--space-2); margin-bottom: var(--space-3); }
  .form-row label { font-weight: 500; font-size: var(--text-sm); }
  .form-row input, .form-row select { padding: 0.5rem; border: 1px solid var(--color-border); border-radius: var(--radius-md); background: var(--color-bg-input); color: var(--color-text); font-size: var(--text-sm); }
  .form-actions { display: flex; gap: var(--space-2); justify-content: flex-end; margin-top: var(--space-3); }
  .btn { padding: 0.5rem 1rem; border-radius: var(--radius-md); font-weight: 500; border: none; cursor: pointer; font-size: var(--text-sm); }
  .btn-primary { background: var(--color-primary); color: white; }
  .btn-primary:hover { background: var(--color-primary-hover); }
  .btn-cancel { background: var(--color-bg-hover); color: var(--color-text); border: 1px solid var(--color-border); }
  .required { color: var(--color-red); }
</style>
