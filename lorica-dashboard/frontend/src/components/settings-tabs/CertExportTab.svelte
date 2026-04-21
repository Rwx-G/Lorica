<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { api, type CertExportAclResponse, type CertExportOrphan } from '../../lib/api';
  import {
    parseOctalMode,
    validateAbsolutePath,
    validateCertExportPattern,
    validateOctalMode,
    validatePosixId,
  } from '../../lib/validators';
  import { showToast } from '../../lib/toast';
  import ConfirmDialog from '../ConfirmDialog.svelte';

  /**
   * Form shape for the cert-export section. The fields on the
   * backend are typed (u32, bool) but we bind them here as the
   * user-facing representation: modes are entered in octal and
   * uids/gids are free-form text so an empty input means "unset".
   */
  interface CertExportFormShape {
    cert_export_enabled: boolean;
    cert_export_dir: string;
    cert_export_owner_uid: string;
    cert_export_group_gid: string;
    cert_export_file_mode: string;
    cert_export_dir_mode: string;
  }

  interface Props {
    settingsForm: CertExportFormShape;
    expanded: boolean;
    toggleSection: () => void;
    onSave: () => void | Promise<void>;
    settingsSaving: boolean;
    settingsMsg: string;
    settingsError: string;
  }

  let {
    settingsForm = $bindable(),
    expanded,
    toggleSection,
    onSave,
    settingsSaving,
    settingsMsg: _settingsMsg,
    settingsError,
  }: Props = $props();

  // Field-level blur/input validators. Null = clean.
  let dirErr = $state<string | null>(null);
  let uidErr = $state<string | null>(null);
  let gidErr = $state<string | null>(null);
  let fileModeErr = $state<string | null>(null);
  let dirModeErr = $state<string | null>(null);

  function checkDir() {
    dirErr = validateAbsolutePath(settingsForm.cert_export_dir);
    if (!dirErr && settingsForm.cert_export_enabled && settingsForm.cert_export_dir.trim() === '') {
      dirErr = 'required when the export is enabled';
    }
  }
  function checkUid() { uidErr = validatePosixId(settingsForm.cert_export_owner_uid); }
  function checkGid() { gidErr = validatePosixId(settingsForm.cert_export_group_gid); }
  function checkFileMode() { fileModeErr = validateOctalMode(settingsForm.cert_export_file_mode); }
  function checkDirMode() { dirModeErr = validateOctalMode(settingsForm.cert_export_dir_mode); }

  // --- ACL list state ---
  let acls: CertExportAclResponse[] = $state([]);
  let aclsLoading = $state(false);
  let aclsError = $state('');
  let deletingAcl: CertExportAclResponse | null = $state(null);

  // --- "Add ACL" inline form ---
  let newPattern = $state('');
  let newUid = $state('');
  let newGid = $state('');
  let newPatternErr = $state<string | null>(null);
  let newUidErr = $state<string | null>(null);
  let newGidErr = $state<string | null>(null);
  let addingAcl = $state(false);

  function checkNewPattern() { newPatternErr = validateCertExportPattern(newPattern); }
  function checkNewUid() { newUidErr = validatePosixId(newUid); }
  function checkNewGid() { newGidErr = validatePosixId(newGid); }

  // --- Reapply state ---
  let reapplying = $state(false);
  let reapplyMsg = $state('');
  let reapplyOk = $state(false);

  // --- Orphan sweep state ---
  let orphans: CertExportOrphan[] = $state([]);
  let orphansLoading = $state(false);
  let orphansError = $state('');
  let orphansEnabled = $state(true);
  let deletingOrphan: CertExportOrphan | null = $state(null);

  async function loadAcls() {
    aclsLoading = true;
    aclsError = '';
    const res = await api.listCertExportAcls();
    if (res.error) {
      aclsError = res.error.message;
    } else if (res.data) {
      acls = res.data.acls;
    }
    aclsLoading = false;
  }

  async function addAcl(e: Event) {
    e.preventDefault();
    checkNewPattern();
    checkNewUid();
    checkNewGid();
    if (newPatternErr || newUidErr || newGidErr) return;
    addingAcl = true;
    const body = {
      hostname_pattern: newPattern.trim(),
      allowed_uid: newUid.trim() === '' ? null : Number(newUid.trim()),
      allowed_gid: newGid.trim() === '' ? null : Number(newGid.trim()),
    };
    const res = await api.createCertExportAcl(body);
    if (res.error) {
      showToast(`Failed to add ACL: ${res.error.message}`, 'error');
    } else {
      showToast('ACL added.', 'success');
      newPattern = '';
      newUid = '';
      newGid = '';
      newPatternErr = null;
      newUidErr = null;
      newGidErr = null;
      await loadAcls();
    }
    addingAcl = false;
  }

  async function confirmDelete() {
    if (!deletingAcl) return;
    const id = deletingAcl.id;
    deletingAcl = null;
    const res = await api.deleteCertExportAcl(id);
    if (res.error) {
      showToast(`Failed to delete ACL: ${res.error.message}`, 'error');
    } else {
      showToast('ACL deleted.', 'success');
      await loadAcls();
    }
  }

  async function loadOrphans() {
    orphansLoading = true;
    orphansError = '';
    const res = await api.listCertExportOrphans();
    if (res.error) {
      orphansError = res.error.message;
    } else if (res.data) {
      orphans = res.data.orphans;
      orphansEnabled = res.data.enabled;
    }
    orphansLoading = false;
  }

  async function confirmDeleteOrphan() {
    if (!deletingOrphan) return;
    const name = deletingOrphan.name;
    deletingOrphan = null;
    const res = await api.deleteCertExportOrphan(name);
    if (res.error) {
      showToast(`Failed to delete ${name}: ${res.error.message}`, 'error');
    } else {
      showToast(`Orphan ${name} removed.`, 'success');
      await loadOrphans();
    }
  }

  function formatBytes(n: number): string {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
    return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
  }

  function formatTimestamp(ts: string): string {
    if (!ts) return '-';
    const d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    return d.toLocaleString();
  }

  async function reapply() {
    reapplying = true;
    reapplyMsg = '';
    reapplyOk = false;
    const res = await api.reapplyCertExport();
    if (res.error) {
      reapplyMsg = res.error.message || 'Re-export failed';
      reapplyOk = false;
    } else if (res.data) {
      if (!res.data.enabled) {
        reapplyMsg = 'Export is disabled. Enable it above and save first.';
        reapplyOk = false;
      } else {
        const parts: string[] = [`${res.data.exported} exported`];
        if (res.data.skipped > 0) parts.push(`${res.data.skipped} skipped (no ACL)`);
        if (res.data.failed > 0) parts.push(`${res.data.failed} failed`);
        reapplyMsg = parts.join(', ');
        reapplyOk = res.data.failed === 0;
      }
    }
    reapplying = false;
    setTimeout(() => { reapplyMsg = ''; }, 10000);
  }

  function maskedMode(decimal: string): string {
    const n = parseOctalMode(decimal);
    if (n === null) return '';
    return `0o${n.toString(8).padStart(3, '0')}`;
  }

  let aclsRefreshTimer: ReturnType<typeof setInterval> | null = null;
  onMount(() => {
    loadAcls();
    loadOrphans();
    // Refresh the ACL list every 30s so two admins editing the
    // same settings page do not drift. Cheap call, authenticated,
    // no state mutation.
    aclsRefreshTimer = setInterval(loadAcls, 30_000);
  });
  onDestroy(() => {
    if (aclsRefreshTimer) clearInterval(aclsRefreshTimer);
  });

  let hasAnyFieldErr = $derived(
    !!dirErr || !!uidErr || !!gidErr || !!fileModeErr || !!dirModeErr
  );
</script>

<section class="settings-section">
  <button class="settings-collapsible-header" class:open={expanded} onclick={toggleSection}>
    <h2>Certificate export (filesystem)</h2>
    <span class="settings-chevron" class:expanded></span>
  </button>
  {#if expanded}
    <div class="settings-section-body">
      <div class="cert-export-warning" role="alert">
        <strong>Warning.</strong> When this feature is enabled, every
        certificate's <code>privkey.pem</code> is written <strong>in
        plaintext</strong> to the export directory. Private-key
        material only lives on disk where you explicitly put it.
        Restrict ownership (operator UID / group GID), keep the
        file mode at <code>0o640</code> or stricter, and make sure
        the directory itself is on an encrypted volume.
      </div>

      <p class="section-hint">
        Writes <code>cert.pem</code> / <code>chain.pem</code> /
        <code>fullchain.pem</code> / <code>privkey.pem</code> under
        <code>&lt;dir&gt;/&lt;hostname&gt;/</code> every time a cert
        is issued or renewed. External tools (Ansible, HAProxy
        sidecar, a backup job) can then pick up the live bundle
        directly from disk. Pair with per-pattern ACLs below to
        narrow which hostnames are exported and under which
        operator UID / GID.
      </p>

      <div class="settings-form-row">
        <label class="toggle-row">
          <input type="checkbox" bind:checked={settingsForm.cert_export_enabled} />
          Enable filesystem certificate export
        </label>
      </div>

      <div class="settings-form-row">
        <label for="cert-export-dir">Export directory</label>
        <input
          id="cert-export-dir"
          type="text"
          bind:value={settingsForm.cert_export_dir}
          placeholder="/var/lib/lorica/exported-certs"
          autocomplete="off"
          onblur={checkDir} oninput={checkDir}
        />
        {#if dirErr}<span class="field-error" role="alert">{dirErr}</span>{/if}
        <span class="hint">
          Absolute path. Created on first export with the
          configured directory mode. The systemd unit grants
          <code>ReadWritePaths=</code> to
          <code>/var/lib/lorica/exported-certs</code> out of the
          box; point elsewhere only if you also loosen the unit
          sandbox.
        </span>
      </div>

      <h3>Permissions</h3>

      <div class="perm-grid">
        <div class="settings-form-row">
          <label for="cert-export-uid">Owner UID</label>
          <input
            id="cert-export-uid"
            type="text"
            inputmode="numeric"
            bind:value={settingsForm.cert_export_owner_uid}
            placeholder="1001"
            autocomplete="off"
            onblur={checkUid} oninput={checkUid}
          />
          {#if uidErr}<span class="field-error" role="alert">{uidErr}</span>{/if}
          <span class="hint">Leave empty to keep the Lorica process UID.</span>
        </div>

        <div class="settings-form-row">
          <label for="cert-export-gid">Group GID</label>
          <input
            id="cert-export-gid"
            type="text"
            inputmode="numeric"
            bind:value={settingsForm.cert_export_group_gid}
            placeholder="2001"
            autocomplete="off"
            onblur={checkGid} oninput={checkGid}
          />
          {#if gidErr}<span class="field-error" role="alert">{gidErr}</span>{/if}
          <span class="hint">Leave empty to keep the Lorica process GID.</span>
        </div>

        <div class="settings-form-row">
          <label for="cert-export-file-mode">
            File mode (octal) <strong>{maskedMode(settingsForm.cert_export_file_mode) || '0o640'}</strong>
          </label>
          <input
            id="cert-export-file-mode"
            type="text"
            bind:value={settingsForm.cert_export_file_mode}
            placeholder="640"
            autocomplete="off"
            onblur={checkFileMode} oninput={checkFileMode}
          />
          {#if fileModeErr}<span class="field-error" role="alert">{fileModeErr}</span>{/if}
          <span class="hint">
            Applied to every <code>.pem</code> file. Default
            <code>640</code> (owner rw, group r, world nothing).
            <code>600</code> if no group reader is needed.
          </span>
        </div>

        <div class="settings-form-row">
          <label for="cert-export-dir-mode">
            Directory mode (octal) <strong>{maskedMode(settingsForm.cert_export_dir_mode) || '0o750'}</strong>
          </label>
          <input
            id="cert-export-dir-mode"
            type="text"
            bind:value={settingsForm.cert_export_dir_mode}
            placeholder="750"
            autocomplete="off"
            onblur={checkDirMode} oninput={checkDirMode}
          />
          {#if dirModeErr}<span class="field-error" role="alert">{dirModeErr}</span>{/if}
          <span class="hint">
            Applied to the root export directory and every
            per-hostname subdirectory. Default <code>750</code>.
          </span>
        </div>
      </div>

      {#if settingsError}
        <div class="settings-form-error">{settingsError}</div>
      {/if}
      <div class="settings-dialog-actions">
        <button
          class="btn btn-primary"
          onclick={onSave}
          disabled={settingsSaving || hasAnyFieldErr}
        >
          {settingsSaving ? 'Saving...' : 'Save Export Settings'}
        </button>
      </div>

      <hr class="section-separator" />

      <h3>Access control (per-pattern ACL)</h3>
      <p class="section-hint">
        ACLs narrow which hostnames are exported and under which
        operator UID / GID. On export, Lorica picks the
        most-specific matching pattern (exact hostname &gt;
        wildcard suffix length &gt; bare <code>*</code>). If no
        pattern matches, the cert is not exported. Patterns
        accept <code>*</code> (all), <code>*.suffix.tld</code>
        (wildcard suffix), or an exact hostname.
      </p>

      <form class="acl-add-form" onsubmit={addAcl}>
        <div class="acl-add-grid">
          <div class="settings-form-row">
            <label for="acl-pattern">Hostname pattern</label>
            <input
              id="acl-pattern"
              type="text"
              bind:value={newPattern}
              placeholder="*.prod.mibu.fr"
              autocomplete="off"
              onblur={checkNewPattern} oninput={checkNewPattern}
            />
            {#if newPatternErr}<span class="field-error" role="alert">{newPatternErr}</span>{/if}
          </div>
          <div class="settings-form-row">
            <label for="acl-uid">Allowed UID</label>
            <input
              id="acl-uid"
              type="text"
              inputmode="numeric"
              bind:value={newUid}
              placeholder="(inherit)"
              autocomplete="off"
              onblur={checkNewUid} oninput={checkNewUid}
            />
            {#if newUidErr}<span class="field-error" role="alert">{newUidErr}</span>{/if}
          </div>
          <div class="settings-form-row">
            <label for="acl-gid">Allowed GID</label>
            <input
              id="acl-gid"
              type="text"
              inputmode="numeric"
              bind:value={newGid}
              placeholder="(inherit)"
              autocomplete="off"
              onblur={checkNewGid} oninput={checkNewGid}
            />
            {#if newGidErr}<span class="field-error" role="alert">{newGidErr}</span>{/if}
          </div>
        </div>
        <div class="acl-add-actions">
          <button
            type="submit"
            class="btn btn-secondary"
            disabled={addingAcl || !!newPatternErr || !!newUidErr || !!newGidErr || newPattern.trim() === ''}
          >
            {addingAcl ? 'Adding...' : 'Add ACL'}
          </button>
        </div>
      </form>

      {#if aclsError}
        <div class="settings-form-error">{aclsError}</div>
      {/if}

      {#if aclsLoading && acls.length === 0}
        <p class="loading">Loading ACLs...</p>
      {:else if acls.length === 0}
        <p class="acl-empty">
          No ACL rules yet. Without at least one pattern, no
          certificate is exported.
        </p>
      {:else}
        <table class="acl-table">
          <thead>
            <tr>
              <th>Pattern</th>
              <th>UID</th>
              <th>GID</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#each acls as acl (acl.id)}
              <tr>
                <td><code>{acl.hostname_pattern}</code></td>
                <td>{acl.allowed_uid ?? '—'}</td>
                <td>{acl.allowed_gid ?? '—'}</td>
                <td><time datetime={acl.created_at}>{new Date(acl.created_at).toLocaleString()}</time></td>
                <td class="acl-row-actions">
                  <button
                    type="button"
                    class="btn btn-danger-subtle"
                    onclick={() => (deletingAcl = acl)}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}

      <hr class="section-separator" />

      <h3>Operator actions</h3>
      <div class="settings-form-row reapply-row">
        <div class="reapply-inner">
          {#if reapplyMsg}
            <span class="test-msg {reapplyOk ? 'test-ok' : 'test-err'}" role="status">
              {reapplyMsg}
            </span>
          {/if}
          <button
            type="button"
            class="btn btn-secondary"
            onclick={reapply}
            disabled={reapplying}
          >
            {reapplying ? 'Re-exporting...' : 'Re-export matching certificates now'}
          </button>
        </div>
        <span class="hint">
          Forces a re-export of every certificate whose hostname
          matches a configured ACL pattern. Useful after changing
          ACLs or default file modes, when you do not want to wait
          for the next ACME renewal to realign on-disk files.
          Honours the currently-persisted settings - save first if
          you just changed them.
        </span>
      </div>

      <h3>Orphan directories</h3>
      <p class="section-hint">
        Per-hostname subdirectories found under the export root that
        no longer correspond to any live certificate. These are the
        residual bytes of a cert you deleted in the dashboard: the
        exporter leaves them in place by design (consumers that
        cached the path keep working on the stale bundle until they
        flip) so you control the removal explicitly here.
      </p>

      {#if !orphansEnabled}
        <p class="acl-empty">Export is disabled ; there is nothing to scan.</p>
      {:else if orphansLoading}
        <p class="loading">Scanning export directory...</p>
      {:else if orphansError}
        <div class="settings-form-error">{orphansError}</div>
      {:else if orphans.length === 0}
        <p class="acl-empty">No orphan directory found. 🎉</p>
      {:else}
        <table class="acl-table">
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Size</th>
              <th>Last modified</th>
              <th aria-label="Actions"></th>
            </tr>
          </thead>
          <tbody>
            {#each orphans as o (o.name)}
              <tr>
                <td><code>{o.name}</code></td>
                <td>{formatBytes(o.size_bytes)}</td>
                <td>{formatTimestamp(o.modified_at)}</td>
                <td class="acl-row-actions">
                  <button
                    type="button"
                    class="btn btn-secondary btn-small"
                    onclick={() => (deletingOrphan = o)}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}

      <div class="settings-form-row orphans-actions">
        <button
          type="button"
          class="btn btn-secondary"
          onclick={loadOrphans}
          disabled={orphansLoading}
        >
          {orphansLoading ? 'Scanning...' : 'Rescan now'}
        </button>
      </div>
    </div>
  {/if}
</section>

{#if deletingOrphan}
  <ConfirmDialog
    title="Delete orphan directory"
    message={`Permanently delete ${deletingOrphan.name}/ from the export directory? The four PEM files (including privkey.pem) will be removed. Any consumer still reading from this path will start failing.`}
    onconfirm={confirmDeleteOrphan}
    oncancel={() => (deletingOrphan = null)}
  />
{/if}

{#if deletingAcl}
  <ConfirmDialog
    title="Delete ACL"
    message={`Delete the ACL for pattern "${deletingAcl.hostname_pattern}"? Exports for matching hostnames will stop until another pattern matches.`}
    onconfirm={confirmDelete}
    oncancel={() => (deletingAcl = null)}
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
  .field-error {
    display: block;
    color: var(--color-red);
    font-size: var(--text-xs);
    margin-top: 0.25rem;
  }
  .cert-export-warning {
    border: 1px solid var(--color-danger, #b32);
    background: var(--color-danger-subtle, rgba(187, 51, 51, 0.1));
    color: var(--color-danger, #b32);
    padding: 0.75rem 1rem;
    border-radius: 4px;
    font-size: 0.875rem;
    margin-bottom: 1rem;
  }
  .toggle-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-weight: 500;
  }
  .perm-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 0.75rem 1rem;
    margin-bottom: 1rem;
  }
  /* No border-top here : the `Access control` h3 + its hint
     already open the section. A separator between the hint and
     the add form would mis-read as "new section" inside what is
     one coherent ACL block (add form + list). */
  .acl-add-form {
    margin-top: 0.5rem;
  }
  .acl-add-grid {
    display: grid;
    grid-template-columns: 2fr 1fr 1fr;
    gap: 0.5rem 1rem;
  }
  @media (max-width: 640px) {
    .acl-add-grid {
      grid-template-columns: 1fr;
    }
  }
  .acl-add-actions {
    margin-top: 0.5rem;
  }
  .acl-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.875rem;
    margin-top: 0.75rem;
  }
  .acl-table th {
    text-align: left;
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--color-border);
    font-weight: 600;
  }
  .acl-table td {
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--color-border);
    vertical-align: middle;
  }
  .acl-row-actions {
    text-align: right;
  }
  .acl-empty {
    font-size: 0.875rem;
    color: var(--color-text-muted);
    margin: 0.75rem 0 0;
  }
  /* Plain h3 typography. Cross-section separators are explicit
     `<hr class="section-separator">` elements below, placed only
     where a category boundary exists (after `Save Export
     Settings` and at the end of the ACL block). Permissions is
     a sub-section of the main export config, so no separator
     above its h3. */
  h3 {
    margin: var(--space-4) 0 var(--space-2);
    font-size: var(--text-md);
    color: var(--color-text-heading);
  }
  /* Separator between two full sub-sections. Deliberately
     distinct from the ACL / orphan table bottom borders that
     share the same `--color-border` : extra vertical breathing
     room above AND below so the reader does not read the hr as
     "last row of the table". */
  .section-separator {
    border: 0;
    border-top: 1px solid var(--color-border-strong, var(--color-text-muted));
    margin: var(--space-6) 0 var(--space-4);
  }
  /* The h3 above now carries the section separator, so this row
     only needs internal spacing for the inner flex. */
  .reapply-row {
    margin-top: 0.5rem;
  }
  /* Right-align the action row so the button matches the
     `Save Export Settings` position (both read as per-section
     primary actions). Status msg sits to the left of the button
     so the reading order is "result, action" - natural after a
     click where the operator glances back to confirm the
     outcome. */
  .reapply-inner {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 0.75rem;
    margin-bottom: 0.25rem;
  }
  /* Right-align the rescan button so it reads as a deliberate
     action row, matching the `settings-dialog-actions` pattern
     used for `Save Export Settings` above. */
  .orphans-actions {
    display: flex;
    justify-content: flex-end;
    margin-top: 0.75rem;
  }
  .test-msg {
    font-size: 0.8125rem;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
  }
  .test-ok {
    color: var(--color-green, #1a7f37);
    background: var(--color-green-subtle, rgba(26, 127, 55, 0.1));
  }
  .test-err {
    color: var(--color-danger, #b32);
    background: var(--color-danger-subtle, rgba(187, 51, 51, 0.1));
  }
  .loading {
    font-size: 0.875rem;
    color: var(--color-text-muted);
  }
</style>
