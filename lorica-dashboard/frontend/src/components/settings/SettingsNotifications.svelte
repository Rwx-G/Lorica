<script lang="ts">
  import {
    api,
    type NotificationConfigResponse,
  } from '../../lib/api';
  import ConfirmDialog from '../ConfirmDialog.svelte';
  import { showToast } from '../../lib/toast';

  let {
    notifications = $bindable([]),
    expandedSections = $bindable({}),
    toggleSection,
    onReload,
  }: {
    notifications: NotificationConfigResponse[];
    expandedSections: Record<string, boolean>;
    toggleSection: (key: string) => void;
    onReload: () => Promise<void>;
  } = $props();

  // Notification form state
  let showNotifForm = $state(false);
  let notifEditing: NotificationConfigResponse | null = $state(null);
  let notifChannel = $state('email');
  let notifEnabled = $state(true);
  let notifConfig = $state('');
  // Email fields
  let notifSmtpHost = $state('');
  let notifSmtpPort = $state(587);
  let notifSmtpUsername = $state('');
  let notifSmtpPassword = $state('');
  let notifFromAddress = $state('');
  let notifToAddress = $state('');
  // Webhook/Slack fields
  let notifUrl = $state('');
  let notifAuthHeader = $state('');
  // Alert type checkboxes
  let notifAlertBackendDown = $state(false);
  let notifAlertCertExpiring = $state(false);
  let notifAlertWafAlert = $state(false);
  let notifAlertConfigChanged = $state(false);
  let notifAlertSlaBreached = $state(false);
  let notifAlertIpBanned = $state(false);
  let notifError = $state('');
  let notifSaving = $state(false);
  let deletingNotif: NotificationConfigResponse | null = $state(null);
  let testingNotif = $state('');

  function openNotifCreate() {
    notifEditing = null;
    notifChannel = 'email';
    notifEnabled = true;
    notifConfig = '';
    notifSmtpHost = '';
    notifSmtpPort = 587;
    notifSmtpUsername = '';
    notifSmtpPassword = '';
    notifFromAddress = '';
    notifToAddress = '';
    notifUrl = '';
    notifAuthHeader = '';
    notifAlertBackendDown = false;
    notifAlertCertExpiring = false;
    notifAlertWafAlert = false;
    notifAlertConfigChanged = false;
    notifAlertSlaBreached = false;
    notifAlertIpBanned = false;
    notifError = '';
    showNotifForm = true;
  }

  function openNotifEdit(nc: NotificationConfigResponse) {
    notifEditing = nc;
    notifChannel = nc.channel;
    notifEnabled = nc.enabled;
    notifConfig = nc.config;

    // Parse config JSON into individual fields
    try {
      const cfg = JSON.parse(nc.config);
      if (nc.channel === 'email') {
        notifSmtpHost = cfg.smtp_host || '';
        notifSmtpPort = cfg.smtp_port || 587;
        notifSmtpUsername = cfg.smtp_username || '';
        notifSmtpPassword = ''; // masked, don't populate
        notifFromAddress = cfg.from_address || '';
        notifToAddress = cfg.to_address || '';
        notifUrl = '';
        notifAuthHeader = '';
      } else {
        notifUrl = cfg.url || '';
        notifAuthHeader = cfg.auth_header || '';
        notifSmtpHost = '';
        notifSmtpPort = 587;
        notifSmtpUsername = '';
        notifSmtpPassword = '';
        notifFromAddress = '';
        notifToAddress = '';
      }
    } catch {
      // ignore parse errors, fields stay at defaults
    }

    // Populate alert type checkboxes
    const types = nc.alert_types || [];
    notifAlertBackendDown = types.includes('backend_down');
    notifAlertCertExpiring = types.includes('cert_expiring');
    notifAlertWafAlert = types.includes('waf_alert');
    notifAlertConfigChanged = types.includes('config_changed');
    notifAlertSlaBreached = types.includes('sla_breached');
    notifAlertIpBanned = types.includes('ip_banned');

    notifError = '';
    showNotifForm = true;
  }

  async function saveNotification() {
    notifSaving = true;
    notifError = '';

    // Build config JSON from individual fields
    let configObj: Record<string, unknown>;
    if (notifChannel === 'email') {
      configObj = {
        smtp_host: notifSmtpHost,
        smtp_port: notifSmtpPort,
        from_address: notifFromAddress,
        to_address: notifToAddress,
      };
      if (notifSmtpUsername) configObj.smtp_username = notifSmtpUsername;
      if (notifSmtpPassword) configObj.smtp_password = notifSmtpPassword;
      else if (notifEditing) configObj.smtp_password = '********'; // preserve existing
    } else {
      configObj = { url: notifUrl };
      if (notifChannel === 'webhook' && notifAuthHeader) configObj.auth_header = notifAuthHeader;
    }
    const configStr = JSON.stringify(configObj);

    // Build alert_types array from checkboxes
    const alertArr: string[] = [];
    if (notifAlertBackendDown) alertArr.push('backend_down');
    if (notifAlertCertExpiring) alertArr.push('cert_expiring');
    if (notifAlertWafAlert) alertArr.push('waf_alert');
    if (notifAlertConfigChanged) alertArr.push('config_changed');
    if (notifAlertSlaBreached) { alertArr.push('sla_breached'); alertArr.push('sla_recovered'); }
    if (notifAlertIpBanned) alertArr.push('ip_banned');

    const body = { channel: notifChannel, enabled: notifEnabled, config: configStr, alert_types: alertArr };

    if (notifEditing) {
      const res = await api.updateNotification(notifEditing.id, body);
      if (res.error) { notifError = res.error.message; notifSaving = false; return; }
    } else {
      const res = await api.createNotification(body);
      if (res.error) { notifError = res.error.message; notifSaving = false; return; }
    }
    showNotifForm = false;
    notifSaving = false;
    await onReload();
  }

  async function confirmDeleteNotif() {
    if (!deletingNotif) return;
    await api.deleteNotification(deletingNotif.id);
    deletingNotif = null;
    await onReload();
  }

  async function handleTestNotif(id: string) {
    testingNotif = id;
    const res = await api.testNotification(id);
    if (res.error) {
      showToast(`Test failed: ${res.error.message}`, 'error');
    } else {
      showToast(`Test notification sent via ${res.data?.channel}`, 'success');
    }
    testingNotif = '';
  }
</script>

<!-- Notification Channels -->
<section class="section">
  <button class="collapsible-header" class:open={expandedSections.notifications} onclick={() => toggleSection('notifications')}>
    <h2>Notification Channels</h2>
    <span class="chevron" class:expanded={expandedSections.notifications}></span>
  </button>
  {#if expandedSections.notifications}
    <div class="section-body">
      <p class="section-hint">Stdout logging is always enabled. Configure additional channels below.</p>

      {#if notifications.length === 0}
        <p class="empty-text">No notification channels configured.</p>
      {:else}
        <div class="table-wrap">
          <table class="settings-table">
            <thead>
              <tr>
                <th>Channel</th>
                <th>Alert Types</th>
                <th>Enabled</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each notifications as nc}
                <tr>
                  <td class="capitalize">{nc.channel}</td>
                  <td>{nc.alert_types.join(', ') || '-'}</td>
                  <td>
                    <span class="status-dot" class:enabled={nc.enabled} class:disabled={!nc.enabled}></span>
                    {nc.enabled ? 'Yes' : 'No'}
                  </td>
                  <td class="actions-cell">
                    <button class="btn-table-action btn-table-test" onclick={() => handleTestNotif(nc.id)} disabled={testingNotif === nc.id}>Test</button>
                    <button class="btn-table-action btn-table-edit" onclick={() => openNotifEdit(nc)}>Edit</button>
                    <button class="btn-table-action btn-table-delete" onclick={() => deletingNotif = nc}>Delete</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
      <div class="actions-left">
        <button class="btn btn-primary" onclick={openNotifCreate}>Add Channel</button>
      </div>
    </div>
  {/if}
</section>

<!-- Notification form modal -->
{#if showNotifForm}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="overlay" onclick={(e) => { if (e.target === e.currentTarget) showNotifForm = false; }} onkeydown={(e) => { if (e.key === 'Escape') showNotifForm = false; }} role="dialog" aria-modal="true" tabindex="-1">
    <div class="dialog" role="document">
      <h3>{notifEditing ? 'Edit' : 'Add'} Notification Channel</h3>
      <div class="form-row">
        <label for="notif-channel">Channel</label>
        <select id="notif-channel" bind:value={notifChannel}>
          <option value="email">Email (SMTP)</option>
          <option value="webhook">Webhook (HTTP)</option>
          <option value="slack">Slack</option>
        </select>
      </div>
      <div class="form-row">
        <label for="notif-enabled">
          <input id="notif-enabled" type="checkbox" bind:checked={notifEnabled} />
          Enabled
        </label>
      </div>

      {#if notifChannel === 'email'}
        <fieldset class="notif-fieldset">
          <legend>SMTP Server</legend>
          <div class="form-row">
            <label for="notif-smtp-host">SMTP Host <span class="required">*</span></label>
            <input id="notif-smtp-host" type="text" bind:value={notifSmtpHost} placeholder="smtp.example.com" required />
          </div>
          <div class="form-row">
            <label for="notif-smtp-port">SMTP Port</label>
            <input id="notif-smtp-port" type="number" bind:value={notifSmtpPort} placeholder="587" min="1" max="65535" />
            <span class="form-hint">587 (STARTTLS) or 465 (SSL)</span>
          </div>
          <div class="form-row">
            <label for="notif-smtp-user">Username</label>
            <input id="notif-smtp-user" type="text" bind:value={notifSmtpUsername} placeholder="user@example.com" />
          </div>
          <div class="form-row">
            <label for="notif-smtp-pass">Password</label>
            <input id="notif-smtp-pass" type="password" bind:value={notifSmtpPassword} placeholder={notifEditing ? 'Leave empty to keep current' : ''} />
          </div>
        </fieldset>
        <fieldset class="notif-fieldset">
          <legend>Addresses</legend>
          <div class="form-row">
            <label for="notif-from">From <span class="required">*</span></label>
            <input id="notif-from" type="email" bind:value={notifFromAddress} placeholder="noreply@example.com" required />
          </div>
          <div class="form-row">
            <label for="notif-to">To <span class="required">*</span></label>
            <input id="notif-to" type="email" bind:value={notifToAddress} placeholder="admin@example.com" required />
          </div>
        </fieldset>
      {:else}
        <div class="form-row">
          <label for="notif-url">URL <span class="required">*</span></label>
          <input id="notif-url" type="url" bind:value={notifUrl} placeholder={notifChannel === 'slack' ? 'https://hooks.slack.com/services/T.../B.../xxx' : 'https://example.com/webhook'} required />
        </div>
        {#if notifChannel === 'webhook'}
          <div class="form-row">
            <label for="notif-auth">Authorization Header</label>
            <input id="notif-auth" type="text" bind:value={notifAuthHeader} placeholder="Bearer your-token" />
            <span class="form-hint">Optional - sent as Authorization header</span>
          </div>
        {/if}
      {/if}

      <fieldset class="notif-fieldset">
        <legend>Alert Types</legend>
        <div class="alert-select-all">
          <button type="button" class="btn-link" onclick={() => { notifAlertBackendDown = notifAlertCertExpiring = notifAlertWafAlert = notifAlertConfigChanged = notifAlertSlaBreached = notifAlertIpBanned = true; }}>Select all</button>
          <span class="separator">|</span>
          <button type="button" class="btn-link" onclick={() => { notifAlertBackendDown = notifAlertCertExpiring = notifAlertWafAlert = notifAlertConfigChanged = notifAlertSlaBreached = notifAlertIpBanned = false; }}>None</button>
        </div>
        <div class="alert-checkboxes">
          <label><input type="checkbox" bind:checked={notifAlertBackendDown} /> Backend down</label>
          <label><input type="checkbox" bind:checked={notifAlertCertExpiring} /> Certificate expiring</label>
          <label><input type="checkbox" bind:checked={notifAlertWafAlert} /> WAF alert</label>
          <label><input type="checkbox" bind:checked={notifAlertConfigChanged} /> Configuration changed</label>
          <label><input type="checkbox" bind:checked={notifAlertSlaBreached} /> SLA breached</label>
          <label><input type="checkbox" bind:checked={notifAlertIpBanned} /> IP banned</label>
        </div>
      </fieldset>
      {#if notifError}
        <div class="form-error">{notifError}</div>
      {/if}
      <div class="actions">
        <button class="btn btn-cancel" onclick={() => showNotifForm = false}>Cancel</button>
        <button class="btn btn-primary" onclick={saveNotification} disabled={notifSaving}>
          {notifSaving ? 'Saving...' : 'Save'}
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- Delete notification confirm -->
{#if deletingNotif}
  <ConfirmDialog
    title="Delete Notification Channel"
    message="Are you sure you want to delete the {deletingNotif.channel} notification channel?"
    onconfirm={confirmDeleteNotif}
    oncancel={() => deletingNotif = null}
  />
{/if}

