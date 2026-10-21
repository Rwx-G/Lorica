<script lang="ts">
  import type { AdcsAuthority, AdcsIssueRequest } from '../../lib/api';
  import { adcsRequestSummary } from '../../lib/adcs-issuance';

  interface Props {
    authority: AdcsAuthority;
    request: AdcsIssueRequest;
    submitting?: boolean;
    onconfirm: () => void;
    oncancel: () => void;
  }

  let { authority, request, submitting = false, onconfirm, oncancel }: Props = $props();

  const summary = $derived(adcsRequestSummary(authority, request));

  function handleKeydown(e: KeyboardEvent) {
    // Enter deliberately does not confirm: an issuance cannot be undone
    // from Lorica, so it takes an explicit click on "Issue".
    if (e.key === 'Escape' && !submitting) oncancel();
  }
</script>

<div
  class="overlay"
  role="dialog"
  aria-modal="true"
  aria-labelledby="adcs-confirm-title"
  tabindex="-1"
  onclick={(e) => { if (e.target === e.currentTarget && !submitting) oncancel(); }}
  onkeydown={handleKeydown}
>
  <div class="modal" role="document" data-testid="adcs-issue-confirm">
    <h2 id="adcs-confirm-title">Confirm AD CS issuance</h2>
    <p class="warning" role="note">
      This requests a new certificate from the AD CS authority. The authority
      records the issuance, and it can only be undone by revocation on the
      authority, which Lorica cannot do.
    </p>

    <dl class="summary">
      <dt>Template</dt>
      <dd><code data-testid="adcs-confirm-template">{summary.template}</code></dd>
      <dt>Key type</dt>
      <dd data-testid="adcs-confirm-key-type">{summary.keyType}</dd>
      <dt>Auto-renew</dt>
      <dd>{summary.autoRenew ? 'Yes, once a route uses the certificate' : 'No'}</dd>
    </dl>

    <h3>Subject</h3>
    <dl class="summary" data-testid="adcs-confirm-subject">
      {#each summary.subject as line (line.label)}
        <dt>{line.label}</dt>
        <dd>{line.value}</dd>
      {/each}
    </dl>

    <h3>Subject alternative names ({summary.sans.length})</h3>
    <ul class="sans" data-testid="adcs-confirm-sans">
      {#each summary.sans as san (san)}
        <li><code>{san}</code></li>
      {/each}
    </ul>

    <p class="hint">
      The authority may rewrite or drop subject fields. Lorica shows the
      subject of the certificate it receives.
    </p>

    <div class="form-actions">
      <button class="btn btn-cancel" onclick={oncancel} disabled={submitting}>Cancel</button>
      <button class="btn btn-primary" onclick={onconfirm} disabled={submitting}>
        {submitting ? 'Issuing...' : 'Issue'}
      </button>
    </div>
  </div>
</div>

<style>
  .overlay {
    z-index: 110;
  }
  .warning {
    padding: 0.5rem 0.75rem;
    background: rgba(245, 158, 11, 0.08);
    border-left: 3px solid var(--color-orange, #f59e0b);
    border-radius: 0 0.25rem 0.25rem 0;
    font-size: 0.8125rem;
    line-height: 1.45;
    color: var(--color-text);
  }
  h3 {
    margin: 1rem 0 0.5rem;
    font-size: 0.875rem;
    color: var(--color-text-heading);
  }
  .summary {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.25rem 0.75rem;
    margin: 0;
    font-size: 0.875rem;
  }
  .summary dt {
    color: var(--color-text-muted);
    font-weight: 500;
  }
  .summary dd {
    margin: 0;
    word-break: break-all;
  }
  .sans {
    margin: 0;
    padding-left: 1.25rem;
    font-size: 0.875rem;
    line-height: 1.6;
  }
  .btn {
    padding: 0.5rem 1rem;
    border-radius: 0.375rem;
    font-weight: 500;
    font-size: 0.875rem;
  }
</style>
