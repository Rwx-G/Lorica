<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    type AdcsAuthority,
    type AdcsAuthorityRequest,
    type AdcsAuthoritySummary,
    type AdcsConnectionTestResult,
    type AdcsKeyType,
    type AdcsSubjectDefaults,
    type ApiError,
  } from '../../lib/api';
  import ConfirmDialog from '../ConfirmDialog.svelte';
  import { showToast } from '../../lib/toast';
  import { canWriteRole, isSuperAdminRole } from '../../lib/auth';
  import { nodeRole } from '../../lib/cluster';
  import {
    ADCS_KEY_TYPE_LABELS,
    ADCS_KEY_TYPES,
    ADCS_SUBJECT_FIELDS,
    ADCS_SUBJECT_LABELS,
    isAdcsFollower,
  } from '../../lib/adcs-issuance';

  interface Props {
    expanded: boolean;
    toggleSection: () => void;
  }

  let { expanded, toggleSection }: Props = $props();

  const IDENTITY_CHANGE_MESSAGE =
    'Changing the endpoint, realm, KDC list, principal or endpoint CA bundle clears the stored password, so the service account password must be entered again before saving.';

  type SubjectForm = Record<keyof AdcsSubjectDefaults, string>;

  // Only the fields whose input differs from a plain text box.
  const SUBJECT_INPUT: Partial<
    Record<keyof AdcsSubjectDefaults, { type?: string; maxlength?: number; placeholder?: string }>
  > = {
    country: { maxlength: 2, placeholder: 'FR' },
    organization: { placeholder: 'Example Corp' },
    email: { type: 'email', placeholder: 'pki@corp.example.org' },
  };

  let configured = $state(false);
  let summary = $state<AdcsAuthoritySummary | null>(null);
  // `null` for a Viewer even when `configured` (Epic 13 D18).
  let authority = $state<AdcsAuthority | null>(null);
  let managedOnControlPlane = $state(false);
  let loading = $state(false);
  let loadError = $state('');

  // `isSuperAdmin` / `canWrite` reopen during break-glass, but a
  // follower refuses every AD CS write and test regardless, so the
  // role-only stores are the gates here.
  const follower = $derived(isAdcsFollower($nodeRole, { managed_on_control_plane: managedOnControlPlane }));
  const canEdit = $derived($isSuperAdminRole && !follower);
  const canTest = $derived($canWriteRole && !follower && authority !== null);

  let endpoint = $state('');
  let realm = $state('');
  let kdcs = $state('');
  let principal = $state('');
  let password = $state('');
  let endpointCaPem = $state('');
  let issuingCaPem = $state('');
  let defaultTemplate = $state('');
  // The templates allowed besides the default, which always is.
  let otherTemplates = $state<string[]>([]);
  let templateDraft = $state('');
  let templateError = $state('');
  let defaultKeyType = $state<AdcsKeyType>('rsa2048');
  let subject = $state<SubjectForm>(emptySubject());
  let suffixes = $state('');
  let autoRenewDefault = $state(true);

  let saving = $state(false);
  let formError = $state('');
  let confirmingDelete = $state(false);
  let deleteError = $state('');
  let testing = $state(false);
  let testResult = $state<AdcsConnectionTestResult | null>(null);
  let testError = $state('');

  function emptySubject(): SubjectForm {
    return Object.fromEntries(ADCS_SUBJECT_FIELDS.map((field) => [field, ''])) as SubjectForm;
  }

  function subjectBody(): AdcsSubjectDefaults {
    const out: Partial<AdcsSubjectDefaults> = {};
    for (const field of ADCS_SUBJECT_FIELDS) out[field] = optional(subject[field]);
    return out as AdcsSubjectDefaults;
  }

  function lines(value: string): string[] {
    return value
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
  }

  function optional(value: string): string | null {
    const trimmed = value.trim();
    return trimmed === '' ? null : trimmed;
  }

  function sameList(a: string[], b: string[]): boolean {
    return a.length === b.length && a.every((value, index) => value === b[index]);
  }

  // The API compares template names without regard to ASCII case.
  function sameTemplate(a: string, b: string): boolean {
    return a.trim().toLowerCase() === b.trim().toLowerCase();
  }

  /** The words an operator reads for a refused request. */
  function describe(error: ApiError): string {
    if (error.status === 504) {
      return 'The operation is still finishing on the server. Retry shortly.';
    }
    return error.message;
  }

  function fillForm(from: AdcsAuthority | null): void {
    endpoint = from?.endpoint ?? '';
    realm = from?.realm ?? '';
    kdcs = (from?.kdcs ?? []).join('\n');
    principal = from?.principal ?? '';
    password = '';
    endpointCaPem = from?.endpoint_ca_pem ?? '';
    issuingCaPem = from?.issuing_ca_pem ?? '';
    defaultTemplate = from?.default_template ?? '';
    otherTemplates = (from?.allowed_templates ?? []).filter(
      (name) => !sameTemplate(name, defaultTemplate),
    );
    templateDraft = '';
    templateError = '';
    defaultKeyType = from?.default_key_type ?? 'rsa2048';
    const filled = emptySubject();
    for (const field of ADCS_SUBJECT_FIELDS) filled[field] = from?.subject[field] ?? '';
    subject = filled;
    suffixes = (from?.allowed_suffixes ?? []).join('\n');
    autoRenewDefault = from?.auto_renew_default ?? true;
  }

  async function load(): Promise<void> {
    loading = true;
    loadError = '';
    const res = await api.getAdcsAuthority();
    if (res.error) {
      loadError = describe(res.error);
    } else if (res.data) {
      configured = res.data.configured;
      summary = res.data.summary;
      authority = res.data.authority;
      managedOnControlPlane = res.data.managed_on_control_plane;
      fillForm(authority);
    }
    loading = false;
  }

  onMount(load);

  function addTemplate(): void {
    templateError = '';
    const name = templateDraft.trim();
    if (name === '') return;
    if (sameTemplate(name, defaultTemplate) || otherTemplates.some((kept) => sameTemplate(kept, name))) {
      templateError = `${name} is already allowed.`;
      return;
    }
    otherTemplates = [...otherTemplates, name];
    templateDraft = '';
  }

  function removeTemplate(name: string): void {
    otherTemplates = otherTemplates.filter((kept) => kept !== name);
  }

  // Advisory only: the API normalises what it stores and is the one
  // that refuses, with a 422 this form then shows verbatim.
  const identityChanged = $derived(
    authority !== null &&
      (endpoint.trim() !== authority.endpoint ||
        realm.trim() !== authority.realm ||
        principal.trim() !== authority.principal ||
        !sameList(lines(kdcs), authority.kdcs) ||
        optional(endpointCaPem) !== authority.endpoint_ca_pem),
  );
  const passwordRequired = $derived(authority === null || identityChanged);

  async function save(): Promise<void> {
    formError = '';
    if (passwordRequired && password === '') {
      formError =
        authority === null
          ? 'The service account password is required to create the authority.'
          : IDENTITY_CHANGE_MESSAGE;
      return;
    }
    const body: AdcsAuthorityRequest = {
      endpoint: endpoint.trim(),
      realm: realm.trim(),
      kdcs: lines(kdcs),
      principal: principal.trim(),
      endpoint_ca_pem: optional(endpointCaPem),
      issuing_ca_pem: optional(issuingCaPem),
      default_template: defaultTemplate.trim(),
      // The default may have been retyped to one of these since.
      allowed_templates: otherTemplates.filter((name) => !sameTemplate(name, defaultTemplate)),
      default_key_type: defaultKeyType,
      subject: subjectBody(),
      allowed_suffixes: lines(suffixes),
      auto_renew_default: autoRenewDefault,
      // Omitted, never sent empty: an absent password keeps the stored one.
      ...(password !== '' ? { password } : {}),
    };
    saving = true;
    const res = await api.putAdcsAuthority(body);
    saving = false;
    if (res.error) {
      formError = describe(res.error);
      return;
    }
    if (res.data) {
      testResult = null;
      testError = '';
      showToast('AD CS authority saved.', 'success');
      // Read back rather than patch locally: the summary (failed state
      // and its reason) is the API's to derive.
      await load();
    }
  }

  async function confirmDelete(): Promise<void> {
    confirmingDelete = false;
    deleteError = '';
    const res = await api.deleteAdcsAuthority();
    if (res.error) {
      deleteError = describe(res.error);
      return;
    }
    configured = false;
    summary = null;
    authority = null;
    fillForm(null);
    testResult = null;
    testError = '';
    showToast('AD CS authority deleted.', 'success');
  }

  async function runTest(): Promise<void> {
    testing = true;
    testResult = null;
    testError = '';
    const res = await api.testAdcsAuthority();
    testing = false;
    if (res.error) {
      testError = describe(res.error);
      return;
    }
    if (res.data) {
      testResult = res.data;
      // The failed state lives on the authority row; read it back so
      // the banner below shows since, step and KDC code.
      if (res.data.authority_failed) await load();
    }
  }

  function when(value: string): string {
    return new Date(value).toLocaleString();
  }
</script>

<section class="settings-section">
  <button class="settings-collapsible-header" class:open={expanded} aria-expanded={expanded} onclick={toggleSection}>
    <h2>AD CS authority</h2>
    <span class="settings-chevron" class:expanded></span>
  </button>
  {#if expanded}
    <div class="settings-section-body">
      <p class="settings-hint">
        The Active Directory Certificate Services authority Lorica requests
        certificates from, through its Certificate Enrollment Web Service with
        Kerberos. One authority per installation. Only a SuperAdmin may change
        it; an Operator may test the connection.
      </p>

      {#if loadError}
        <div class="settings-form-error" role="alert">{loadError}</div>
      {/if}
      {#if loading}
        <p class="settings-hint">Loading...</p>
      {/if}

      {#if follower}
        <p class="notice" role="status" data-testid="adcs-follower-notice">
          The AD CS authority is managed on the control plane. This node is a
          follower: it holds no authority and runs no AD CS operation. Open this
          page on the control plane to view or change it.
        </p>
      {:else if !loading && !loadError}
        {#if summary?.failed_since}
          <div class="failed-state" role="alert" data-testid="adcs-failed-state">
            <strong>The authority is in the failed state.</strong>
            The KDC rejected the service account's credential, and every AD CS
            operation is suspended so that no further attempt locks the account.
            <dl>
              <dt>Since</dt>
              <dd>{when(summary.failed_since)}</dd>
              <dt>Step</dt>
              <dd><code>{summary.failed_step ?? 'unknown'}</code></dd>
              <dt>KDC code</dt>
              <dd>
                {#if summary.failed_kdc_code !== null}
                  {summary.failed_kdc_code}
                  {#if summary.failed_reason}({summary.failed_reason}){/if}
                {:else}
                  not reported
                {/if}
              </dd>
            </dl>
            Saving a new password clears this state. Fix the account in the
            directory first.
          </div>
        {/if}

        {#if !configured && !canEdit}
          <p class="settings-empty-text">No AD CS authority is configured.</p>
        {:else if authority === null && !canEdit}
          <div class="summary-view" data-testid="adcs-summary">
            <p class="settings-hint">
              An AD CS authority is configured. Its connection details are shown
              to Operators and SuperAdmins only.
            </p>
            <h3>Allowed DNS suffixes</h3>
            <ul class="suffix-list">
              {#each summary?.allowed_suffixes ?? [] as suffix (suffix)}
                <li><code>{suffix}</code></li>
              {/each}
            </ul>
          </div>
        {:else}
          <fieldset class="adcs-form" disabled={!canEdit}>
            <legend class="sr-only">AD CS authority settings</legend>

            <h3>Connection</h3>

            <div class="settings-form-row">
              <label for="adcs-endpoint">CES endpoint <span class="settings-required">*</span></label>
              <input
                id="adcs-endpoint"
                type="url"
                bind:value={endpoint}
                placeholder="https://ces.corp.example.org/CORP-CA_CES_Kerberos/service.svc/CES"
                autocomplete="off"
                spellcheck="false"
              />
              <span class="settings-hint">
                An <code>https://</code> URL with a DNS host name: the service
                ticket is requested for <code>HTTP/&lt;host&gt;</code>.
              </span>
            </div>

            <div class="settings-form-row">
              <label for="adcs-realm">Kerberos realm <span class="settings-required">*</span></label>
              <input
                id="adcs-realm"
                type="text"
                bind:value={realm}
                placeholder="CORP.EXAMPLE.ORG"
                autocomplete="off"
                spellcheck="false"
              />
              <span class="settings-hint">Upper case letters, digits, dots and hyphens.</span>
            </div>

            <div class="settings-form-row">
              <label for="adcs-kdcs">KDCs</label>
              <textarea
                id="adcs-kdcs"
                rows="2"
                bind:value={kdcs}
                placeholder="dc01.corp.example.org&#10;dc02.corp.example.org:88"
                autocomplete="off"
                spellcheck="false"
              ></textarea>
              <span class="settings-hint">
                One <code>host[:port]</code> per line. Leave empty to discover the
                KDCs through DNS SRV records.
              </span>
            </div>

            <div class="settings-form-row">
              <label for="adcs-principal">Service principal <span class="settings-required">*</span></label>
              <input
                id="adcs-principal"
                type="text"
                bind:value={principal}
                placeholder="svc-lorica or svc-lorica@CORP.EXAMPLE.ORG"
                autocomplete="off"
                spellcheck="false"
              />
            </div>

            <p class="password-state">
              Stored password:
              <strong data-testid="adcs-password-state">
                {authority?.password_set ? 'set' : 'not set'}
              </strong>
            </p>

            {#if canEdit}
              <div class="settings-form-row">
                <label for="adcs-password">
                  Service account password
                  {#if passwordRequired}<span class="settings-required">*</span>{/if}
                </label>
                <input
                  id="adcs-password"
                  type="password"
                  bind:value={password}
                  autocomplete="new-password"
                />
                <span class="settings-hint">
                  Write-only: it is stored encrypted and never shown again.
                  {authority === null
                    ? 'Required to create the authority.'
                    : 'Leave empty to keep the stored password.'}
                </span>
                {#if identityChanged}
                  <span class="identity-warning" role="status" data-testid="adcs-identity-warning">
                    {IDENTITY_CHANGE_MESSAGE}
                  </span>
                {/if}
              </div>
            {/if}

            <div class="settings-form-row">
              <label for="adcs-endpoint-ca">Endpoint CA bundle (PEM)</label>
              <textarea
                id="adcs-endpoint-ca"
                rows="4"
                bind:value={endpointCaPem}
                placeholder="-----BEGIN CERTIFICATE-----"
                spellcheck="false"
              ></textarea>
              <span class="settings-hint">
                Certificates trusted, alone, for the CES endpoint's TLS
                certificate. Empty uses the system trust store. Changing it
                clears the stored password, like the fields above.
              </span>
            </div>

            <h3>Issuance defaults</h3>

            <div class="settings-form-row">
              <label for="adcs-issuing-ca">Issuing CA certificate (PEM)</label>
              <textarea
                id="adcs-issuing-ca"
                rows="4"
                bind:value={issuingCaPem}
                placeholder="-----BEGIN CERTIFICATE-----"
                spellcheck="false"
              ></textarea>
              <span class="settings-hint">
                The CA that signs Lorica's certificates. Learned from the first
                issuance when left empty.
              </span>
            </div>

            <div class="settings-form-row">
              <label for="adcs-template">Default template <span class="settings-required">*</span></label>
              <input
                id="adcs-template"
                type="text"
                bind:value={defaultTemplate}
                placeholder="LoricaWebServer"
                autocomplete="off"
                spellcheck="false"
              />
              <span class="settings-hint">
                The template's common name, not its display name: the CA refuses
                a display name as an unknown template.
              </span>
            </div>

            <div class="settings-form-row">
              <span class="field-label" id="adcs-allowed-templates-label">Allowed templates</span>
              <ul class="template-list" aria-labelledby="adcs-allowed-templates-label" data-testid="adcs-allowed-templates">
                <li>
                  <code>{defaultTemplate.trim() || 'the default template'}</code>
                  <span class="template-fixed">default, always allowed</span>
                </li>
                {#each otherTemplates as name (name)}
                  <li>
                    <code>{name}</code>
                    {#if canEdit}
                      <button
                        type="button"
                        class="template-remove"
                        aria-label="Remove template {name}"
                        onclick={() => removeTemplate(name)}
                      >Remove</button>
                    {/if}
                  </li>
                {/each}
              </ul>
              {#if canEdit}
                <div class="template-add">
                  <label for="adcs-template-add" class="sr-only">Template to allow</label>
                  <input
                    id="adcs-template-add"
                    type="text"
                    bind:value={templateDraft}
                    placeholder="LoricaWebServerEcdsa"
                    autocomplete="off"
                    spellcheck="false"
                    onkeydown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addTemplate(); } }}
                  />
                  <button type="button" class="btn btn-cancel" onclick={addTemplate}>Allow template</button>
                </div>
                {#if templateError}
                  <span class="field-error" role="alert">{templateError}</span>
                {/if}
              {/if}
              <span class="settings-hint">
                The templates an issuance may request, by common name. The
                template decides what the authority signs, so any other is
                refused before the authority is contacted.
              </span>
            </div>

            <div class="settings-form-row">
              <label for="adcs-key-type">Default key type</label>
              <select id="adcs-key-type" bind:value={defaultKeyType}>
                {#each ADCS_KEY_TYPES as keyType (keyType)}
                  <option value={keyType}>{ADCS_KEY_TYPE_LABELS[keyType]}</option>
                {/each}
              </select>
              <span class="settings-hint">
                ECDSA P-256 needs a template at schema version 3 or later with a
                key storage provider; a version 2 template duplicated from Web
                Server handles RSA only.
              </span>
            </div>

            <div class="subject-grid">
              {#each ADCS_SUBJECT_FIELDS as field (field)}
                <div class="settings-form-row">
                  <label for="adcs-subject-{field}">{ADCS_SUBJECT_LABELS[field]}</label>
                  <input
                    id="adcs-subject-{field}"
                    type={SUBJECT_INPUT[field]?.type ?? 'text'}
                    maxlength={SUBJECT_INPUT[field]?.maxlength}
                    placeholder={SUBJECT_INPUT[field]?.placeholder}
                    bind:value={subject[field]}
                    autocomplete="off"
                  />
                </div>
              {/each}
            </div>
            <span class="settings-hint">
              The fixed part of every certificate's subject. The common name is
              the certificate's first name. The authority may rewrite or drop
              these fields; Lorica shows the subject it receives.
            </span>

            <div class="settings-form-row">
              <label for="adcs-suffixes">Allowed DNS suffixes <span class="settings-required">*</span></label>
              <textarea
                id="adcs-suffixes"
                rows="3"
                bind:value={suffixes}
                placeholder="corp.example.org"
                autocomplete="off"
                spellcheck="false"
              ></textarea>
              <span class="settings-hint">
                One per line, at least one. An entry permits that name and every
                name under it, matched label by label:
                <code>corp.example.org</code> does not permit
                <code>evilcorp.example.org</code>. Wildcards are refused.
              </span>
            </div>

            <div class="settings-form-row">
              <label class="toggle-label" for="adcs-auto-renew">
                <input id="adcs-auto-renew" type="checkbox" bind:checked={autoRenewDefault} />
                Auto-renew new certificates by default
              </label>
            </div>
          </fieldset>

          {#if formError}
            <div class="settings-form-error" role="alert" data-testid="adcs-form-error">{formError}</div>
          {/if}
          {#if deleteError}
            <div class="settings-form-error" role="alert" data-testid="adcs-delete-error">{deleteError}</div>
          {/if}

          {#if canEdit}
            <div class="settings-dialog-actions">
              {#if authority !== null}
                <button class="btn btn-danger" onclick={() => (confirmingDelete = true)}>
                  Delete authority
                </button>
              {/if}
              <button class="btn btn-primary" onclick={save} disabled={saving}>
                {saving ? 'Saving...' : 'Save AD CS authority'}
              </button>
            </div>
          {/if}
        {/if}

        {#if canTest}
          <h3>Connection test</h3>
          <p class="settings-hint">
            Acquires a ticket for the service account and authenticates to the
            endpoint with the TLS channel binding and mutual authentication. No
            certificate is requested. A rejected password puts the authority in
            the failed state after one attempt.
          </p>
          <div class="settings-dialog-actions test-actions">
            <button class="btn btn-cancel" onclick={runTest} disabled={testing}>
              {testing ? 'Testing...' : 'Test connection'}
            </button>
          </div>
          {#if testError}
            <div class="settings-form-error" role="alert" data-testid="adcs-test-error">{testError}</div>
          {/if}
          {#if testResult}
            {#if testResult.ok}
              <p class="test-ok" role="status" data-testid="adcs-test-result">
                Connection OK: Lorica authenticated to the endpoint.
              </p>
            {:else}
              <div class="test-failed" role="status" data-testid="adcs-test-result">
                Failed at step <code>{testResult.step}</code>: {testResult.message}
                {#if testResult.authority_failed}
                  <br />The KDC rejected the credential: the authority is now in the
                  failed state.
                {/if}
              </div>
            {/if}
          {/if}
        {/if}

        <details class="prerequisites">
          <summary>Authority-side prerequisites</summary>
          <p class="settings-hint">
            Lorica cannot check these from its side. A missing one shows up as a
            failed connection test or a refused request. The operator guide,
            <code>docs/adcs.md</code>, covers each one.
          </p>
          <ul>
            <li>
              A dedicated certificate template: subject mode <em>Supply in the
              request</em>, the <em>Server Authentication</em> EKU only, and
              enrollment restricted to the service account.
            </li>
            <li>The template published on the authority.</li>
            <li>
              <code>EDITF_ATTRIBUTESUBJECTALTNAME2</code> cleared on the
              authority.
            </li>
            <li>The CES instance in Kerberos authentication mode.</li>
            <li>Extended Protection set to <em>Required</em> on the CES application.</li>
            <li>
              The <code>HTTP/ces.corp.example.org</code> SPN registered on the CES
              application pool identity.
            </li>
            <li>AES encryption types enabled on the service account and the pool identity.</li>
            <li>
              A service account password that does not expire, or a documented
              rotation procedure: a stale password stops every AD CS operation.
            </li>
            <li>
              Network flows from Lorica: HTTPS to the CES endpoint, Kerberos on TCP
              and UDP 88 to the KDCs, and DNS.
            </li>
            <li>Time synchronised with the domain: Kerberos refuses a clock skew.</li>
          </ul>
        </details>
      {/if}
    </div>
  {/if}
</section>

{#if confirmingDelete}
  <ConfirmDialog
    title="Delete AD CS authority"
    message="Delete the AD CS authority and its stored password? This is refused while any certificate still references it."
    confirmLabel="Delete"
    onconfirm={confirmDelete}
    oncancel={() => (confirmingDelete = false)}
  />
{/if}

<style>
  h3 {
    margin: var(--space-4) 0 var(--space-2);
    font-size: var(--text-md);
    color: var(--color-text-heading);
    border-top: 1px solid var(--color-border);
    padding-top: var(--space-4);
  }
  .adcs-form {
    border: none;
    padding: 0;
    margin: 0;
    min-width: 0;
  }
  .password-state {
    font-size: 0.8125rem;
    color: var(--color-text-muted);
  }
  .notice {
    padding: 0.75rem;
    border-radius: 0.375rem;
    background: var(--color-primary-subtle);
    color: var(--color-text);
  }
  .failed-state {
    padding: 0.75rem;
    margin-bottom: var(--space-4);
    border: 1px solid var(--color-red);
    border-radius: 0.375rem;
    color: var(--color-red);
    font-size: 0.875rem;
    line-height: 1.5;
  }
  .failed-state dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.25rem 0.75rem;
    margin: 0.5rem 0;
  }
  .failed-state dt {
    font-weight: 600;
  }
  .failed-state dd {
    margin: 0;
  }
  .identity-warning {
    display: block;
    color: var(--color-orange);
    font-size: var(--text-xs);
    margin-top: 0.25rem;
  }
  .summary-view h3 {
    border-top: none;
    padding-top: 0;
  }
  .suffix-list {
    margin: 0;
    padding-left: 1.25rem;
    font-size: 0.875rem;
    line-height: 1.6;
  }
  .field-label {
    display: block;
    font-size: var(--text-sm);
    font-weight: 500;
    margin-bottom: 0.25rem;
  }
  .template-list {
    list-style: none;
    margin: 0 0 0.5rem;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    font-size: 0.875rem;
  }
  .template-list li {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }
  .template-fixed {
    font-size: var(--text-xs);
    color: var(--color-text-muted);
  }
  .template-remove {
    background: none;
    border: none;
    padding: 0;
    font-size: var(--text-xs);
    color: var(--color-red);
    cursor: pointer;
  }
  .template-add {
    display: flex;
    gap: var(--space-2);
  }
  .field-error {
    display: block;
    color: var(--color-red);
    font-size: var(--text-xs);
    margin-top: 0.25rem;
  }
  .subject-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
    gap: 0 var(--space-4);
  }
  .toggle-label {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-size: var(--text-sm);
    color: var(--color-text-muted);
  }
  .test-actions {
    justify-content: flex-start;
  }
  .test-ok {
    color: var(--color-green);
    font-size: 0.875rem;
  }
  .test-failed {
    color: var(--color-red);
    font-size: 0.875rem;
    line-height: 1.5;
  }
  .prerequisites {
    margin-top: var(--space-4);
    border-top: 1px solid var(--color-border);
    padding-top: var(--space-4);
  }
  .prerequisites summary {
    cursor: pointer;
    font-weight: 600;
    color: var(--color-text-heading);
  }
  .prerequisites ul {
    font-size: 0.875rem;
    line-height: 1.6;
    padding-left: 1.25rem;
  }
</style>
