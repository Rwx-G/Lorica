<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    type AdcsAuthorityState,
    type AdcsIssueRequest,
    type AdcsKeyType,
    type AdcsSubjectDefaults,
    type CertificateResponse,
  } from '../../lib/api';
  import {
    ADCS_KEY_TYPES,
    ADCS_KEY_TYPE_LABELS,
    ADCS_SUBJECT_FIELDS,
    ADCS_SUBJECT_LABELS,
    adcsIssuanceBlocker,
    adcsIssueOutcome,
    adcsSanHints,
    parseSanList,
    subjectOverrides,
    type AdcsIssueOutcome,
  } from '../../lib/adcs-issuance';
  import { canWriteRole } from '../../lib/auth';
  import { nodeRole } from '../../lib/cluster';
  import AdcsIssueConfirm from './AdcsIssueConfirm.svelte';

  interface Props {
    onClose: () => void;
    onReload: () => Promise<void>;
    onView: (cert: CertificateResponse) => void;
  }

  let { onClose, onReload, onView }: Props = $props();

  let authorityState = $state<AdcsAuthorityState | null>(null);
  let loading = $state(true);
  let loadError = $state('');

  let sansText = $state('');
  let template = $state('');
  let keyType = $state<AdcsKeyType>('rsa2048');
  let subject = $state<Record<keyof AdcsSubjectDefaults, string>>({
    country: '',
    state: '',
    locality: '',
    organization: '',
    organizational_unit: '',
    email: '',
  });
  let autoRenew = $state(true);

  let formError = $state('');
  let pendingRequest = $state<AdcsIssueRequest | null>(null);
  let submitting = $state(false);
  let outcome = $state<AdcsIssueOutcome | null>(null);

  // `canWriteRole`, not `canWrite`: a follower inside a break-glass
  // window reopens `canWrite`, but the API refuses AD CS issuance on a
  // follower regardless, and the follower test below covers it.
  const blocker = $derived(
    loading || loadError
      ? null
      : adcsIssuanceBlocker({
          canIssue: $canWriteRole,
          follower: $nodeRole === 'follower',
          state: authorityState,
        }),
  );
  const authority = $derived(authorityState?.authority ?? null);
  const sans = $derived(parseSanList(sansText));
  const hints = $derived(adcsSanHints(sans, authority?.allowed_suffixes ?? []));

  onMount(async () => {
    const res = await api.getAdcsAuthority();
    if (res.error) {
      loadError = res.error.message;
    } else if (res.data) {
      authorityState = res.data;
      const from = res.data.authority;
      if (from) {
        template = from.default_template;
        keyType = from.default_key_type;
        for (const field of ADCS_SUBJECT_FIELDS) subject[field] = from.subject[field] ?? '';
        autoRenew = from.auto_renew_default;
      }
    }
    loading = false;
  });

  function review(): void {
    formError = '';
    outcome = null;
    if (!authority) return;
    if (sans.length === 0) {
      formError = 'Enter at least one DNS name.';
      return;
    }
    const trimmedTemplate = template.trim();
    const overrides = subjectOverrides(authority.subject, subject);
    pendingRequest = {
      sans,
      ...(trimmedTemplate !== '' && trimmedTemplate !== authority.default_template
        ? { template: trimmedTemplate }
        : {}),
      ...(keyType !== authority.default_key_type ? { key_type: keyType } : {}),
      ...(overrides ? { subject: overrides } : {}),
      auto_renew: autoRenew,
    };
  }

  async function issue(): Promise<void> {
    if (!pendingRequest) return;
    submitting = true;
    const res = await api.issueAdcsCertificate(pendingRequest);
    submitting = false;
    pendingRequest = null;
    outcome = adcsIssueOutcome(res);
    if (outcome.kind === 'issued') await onReload();
  }
</script>

<div
  class="overlay"
  role="dialog"
  aria-modal="true"
  aria-labelledby="adcs-form-title"
  tabindex="-1"
  onclick={(e) => { if (e.target === e.currentTarget) onClose(); }}
  onkeydown={(e) => { if (e.key === 'Escape' && !pendingRequest) onClose(); }}
>
  <div class="modal" role="document">
    <h2 id="adcs-form-title">AD CS Certificate</h2>

    {#if loading}
      <p class="hint">Loading the AD CS authority...</p>
    {:else if loadError}
      <div class="form-error" role="alert">{loadError}</div>
      <div class="form-actions">
        <button class="btn btn-cancel" onclick={onClose}>Close</button>
      </div>
    {:else if blocker}
      <p class="notice" role="status" data-testid="adcs-issue-unavailable">{blocker}</p>
      <div class="form-actions">
        <button class="btn btn-cancel" onclick={onClose}>Close</button>
      </div>
    {:else if outcome?.kind === 'issued'}
      <div class="success-banner" role="status" data-testid="adcs-issue-outcome">
        Certificate issued and stored.
      </div>
      <dl class="issued">
        <dt>Subject as issued</dt>
        <dd data-testid="adcs-issued-subject">{outcome.certificate.subject || 'not readable from the returned certificate'}</dd>
      </dl>
      <p class="hint">
        This is the subject of the certificate the authority returned. Its
        template may have rewritten the subject that was requested.
      </p>
      <div class="form-actions">
        <button class="btn btn-cancel" onclick={onClose}>Close</button>
        <button
          class="btn btn-primary"
          onclick={() => { if (outcome?.kind === 'issued') onView(outcome.certificate); }}
        >
          View certificate
        </button>
      </div>
    {:else}
      {#if outcome?.kind === 'pending'}
        <div class="form-error" role="alert" data-testid="adcs-issue-outcome">
          The authority answered that the request is pending, under request id
          <code>{outcome.requestId}</code>: {outcome.message}
          Nothing was stored. Templates that need CA manager approval are not
          supported; ask the authority's administrators about this request.
        </div>
      {:else if outcome?.kind === 'refused'}
        <div class="form-error" role="alert" data-testid="adcs-issue-outcome">{outcome.message}</div>
      {/if}
      {#if formError}
        <div class="form-error" role="alert">{formError}</div>
      {/if}

      <div class="form-group">
        <label for="adcs-issue-sans">DNS names <span class="required">*</span></label>
        <textarea
          id="adcs-issue-sans"
          rows="3"
          bind:value={sansText}
          placeholder="app.corp.example.org&#10;www.app.corp.example.org"
          autocomplete="off"
          spellcheck="false"
        ></textarea>
        <span class="hint">
          One per line. The first is the subject's common name. Allowed under:
          {authority?.allowed_suffixes.join(', ')}.
        </span>
        {#if hints.wildcards.length > 0}
          <span class="name-hint" role="status" data-testid="adcs-hint-wildcard">
            Wildcards are refused: {hints.wildcards.join(', ')}.
          </span>
        {/if}
        {#if hints.outsideSuffixes.length > 0}
          <span class="name-hint" role="status" data-testid="adcs-hint-suffix">
            Outside the allowed DNS suffixes, so the API will refuse:
            {hints.outsideSuffixes.join(', ')}.
          </span>
        {/if}
      </div>

      <details class="overrides">
        <summary>Template, key type and subject</summary>
        <div class="form-group">
          <label for="adcs-issue-template">Template</label>
          <input id="adcs-issue-template" type="text" bind:value={template} autocomplete="off" spellcheck="false" />
          <span class="hint">The template's common name. Prefilled with the authority's default.</span>
        </div>
        <div class="form-group">
          <label for="adcs-issue-key-type">Key type</label>
          <select id="adcs-issue-key-type" bind:value={keyType}>
            {#each ADCS_KEY_TYPES as type (type)}
              <option value={type}>{ADCS_KEY_TYPE_LABELS[type]}</option>
            {/each}
          </select>
        </div>
        <div class="form-row">
          {#each ADCS_SUBJECT_FIELDS as field (field)}
            <div class="form-group">
              <label for="adcs-issue-subject-{field}">{ADCS_SUBJECT_LABELS[field]}</label>
              <input id="adcs-issue-subject-{field}" type="text" bind:value={subject[field]} autocomplete="off" />
            </div>
          {/each}
        </div>
        <span class="hint">A field left empty takes the authority's default.</span>
      </details>

      <div class="form-group">
        <label class="checkbox-item">
          <input type="checkbox" bind:checked={autoRenew} />
          Auto-renew
        </label>
      </div>

      <p class="note" data-testid="adcs-unbound-note">
        A certificate issued here is not bound to any route. Lorica only renews
        certificates a route uses, so it is renewed once a route uses it.
      </p>

      <div class="form-actions">
        <button class="btn btn-cancel" onclick={onClose}>Cancel</button>
        <button class="btn btn-primary" onclick={review}>Review request</button>
      </div>
    {/if}
  </div>
</div>

{#if pendingRequest && authority}
  <AdcsIssueConfirm
    {authority}
    request={pendingRequest}
    {submitting}
    onconfirm={issue}
    oncancel={() => (pendingRequest = null)}
  />
{/if}

<style>
  .notice {
    padding: 0.75rem;
    border-radius: 0.375rem;
    background: var(--color-primary-subtle);
    color: var(--color-text);
    font-size: 0.875rem;
    line-height: 1.5;
  }
  .note {
    font-size: 0.8125rem;
    color: var(--color-text-muted);
    line-height: 1.45;
  }
  .name-hint {
    display: block;
    color: var(--color-orange);
    font-size: 0.75rem;
    margin-top: 0.25rem;
  }
  .overrides {
    margin-bottom: 1rem;
  }
  .overrides summary {
    cursor: pointer;
    font-size: 0.875rem;
    font-weight: 500;
    margin-bottom: 0.75rem;
  }
  .success-banner {
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-green);
    border-radius: 0.375rem;
    color: var(--color-green);
    background: var(--color-green-subtle);
    margin-bottom: 1rem;
    font-size: 0.875rem;
  }
  .issued {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.25rem 0.75rem;
    margin: 0;
    font-size: 0.875rem;
  }
  .issued dt {
    color: var(--color-text-muted);
    font-weight: 500;
  }
  .issued dd {
    margin: 0;
    word-break: break-all;
  }
  .btn {
    padding: 0.5rem 1rem;
    border-radius: 0.375rem;
    font-weight: 500;
    font-size: 0.875rem;
  }
</style>
