<script lang="ts">
  import { api, type AdcsAdoptionCandidate } from '../../lib/api';
  import { adcsTemplateLabel, adoptInSequence, type AdcsAdoptionResult } from '../../lib/adcs-adoption';

  interface Props {
    candidates: AdcsAdoptionCandidate[];
    /** The authority's auto-renew default, which each checkbox starts from. */
    autoRenewDefault: boolean;
    onReload: () => Promise<void>;
    onClose: () => void;
  }

  let { candidates, autoRenewDefault, onReload, onClose }: Props = $props();

  let selectedIds = $state<string[]>([]);
  let autoRenewChoices = $state<Record<string, boolean>>({});
  let adopting = $state(false);
  let results = $state<AdcsAdoptionResult[]>([]);

  // A refresh drops adopted certificates from `candidates`; a stale id
  // left in the selection must not be adopted a second time.
  const selected = $derived(candidates.filter((c) => selectedIds.includes(c.certificate_id)));
  const allSelected = $derived(candidates.length > 0 && selected.length === candidates.length);

  function autoRenewOf(id: string): boolean {
    return autoRenewChoices[id] ?? autoRenewDefault;
  }

  function toggle(id: string, checked: boolean) {
    selectedIds = checked ? [...selectedIds, id] : selectedIds.filter((s) => s !== id);
  }

  function toggleAll(checked: boolean) {
    selectedIds = checked ? candidates.map((c) => c.certificate_id) : [];
  }

  function requestedNames(candidate: AdcsAdoptionCandidate): string[] {
    const names = [candidate.domain, ...candidate.san_domains];
    const keys = names.map((name) => name.toLowerCase());
    return names.filter((_, i) => keys.indexOf(keys[i]) === i);
  }

  function formatDate(iso: string): string {
    return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  }

  async function adoptSelected() {
    if (selected.length === 0) return;
    adopting = true;
    results = await adoptInSequence(
      selected,
      (c) => autoRenewOf(c.certificate_id),
      (id, body) => api.adoptAdcsCertificate(id, body),
    );
    selectedIds = [];
    adopting = false;
    await onReload();
  }
</script>

<section class="adoption-panel" aria-label="AD CS adoption" data-testid="adcs-adoption-panel">
  <div class="panel-header">
    <h2>Adopt certificates into the AD CS authority</h2>
    <button class="btn btn-cancel" onclick={onClose}>Close</button>
  </div>
  <p class="note" data-testid="adcs-adoption-note">
    Adoption issues nothing. Each certificate stays in service as it is; the AD CS authority renews it in the
    normal renewal window once a route uses it, or at once on "Renew now". Renewal requests a new key with the
    names and subject below, under the authority's template.
  </p>

  {#if results.length > 0}
    <ul class="results" data-testid="adcs-adoption-results">
      {#each results as result (result.certificateId)}
        <li class:ok={result.ok} role={result.ok ? 'status' : 'alert'}>
          <strong>{result.domain}</strong>: {result.message}
        </li>
      {/each}
    </ul>
  {/if}

  {#if candidates.length === 0}
    <p class="text-muted">No certificate is left to adopt.</p>
  {:else}
    <div class="toolbar">
      <label class="checkbox-item">
        <input
          type="checkbox"
          checked={allSelected}
          disabled={adopting}
          onchange={(e) => toggleAll(e.currentTarget.checked)}
        />
        Select all ({candidates.length})
      </label>
      <button class="btn btn-primary" onclick={adoptSelected} disabled={adopting || selected.length === 0}>
        {adopting ? 'Adopting...' : `Adopt selected (${selected.length})`}
      </button>
    </div>

    <ul class="candidates">
      {#each candidates as candidate (candidate.certificate_id)}
        <li class="candidate" data-testid="adcs-adoption-candidate">
          <label class="checkbox-item domain">
            <input
              type="checkbox"
              aria-label={`Select ${candidate.domain}`}
              checked={selectedIds.includes(candidate.certificate_id)}
              disabled={adopting}
              onchange={(e) => toggle(candidate.certificate_id, e.currentTarget.checked)}
            />
            {candidate.domain}
            <span class="text-muted">expires {formatDate(candidate.not_after)}</span>
          </label>
          <dl class="summary">
            <dt>Names renewal requests</dt>
            <dd>{requestedNames(candidate).join(', ')}</dd>
            <dt>Subject renewal requests</dt>
            <dd class="mono">{candidate.subject || 'not readable'}</dd>
            <dt>Template it was issued with</dt>
            <dd class="mono" data-testid="adcs-issued-template">{adcsTemplateLabel(candidate.issued_template)}</dd>
            <dt>Template observed on Lorica's issuances</dt>
            <dd class="mono" data-testid="adcs-observed-template">{adcsTemplateLabel(candidate.observed_template)}</dd>
          </dl>
          {#if candidate.template_mismatch}
            <p class="warning" role="alert" data-testid="adcs-template-mismatch">
              This certificate was issued with a different template from the one Lorica's issuances carry.
              Renewal requests the authority's template, so the renewed certificate may differ (key usage,
              validity, subject rules). Check the template with the authority's administrators before
              adopting.
            </p>
          {/if}
          <label class="checkbox-item">
            <input
              type="checkbox"
              aria-label={`Auto-renew ${candidate.domain}`}
              checked={autoRenewOf(candidate.certificate_id)}
              disabled={adopting}
              onchange={(e) => (autoRenewChoices[candidate.certificate_id] = e.currentTarget.checked)}
            />
            Auto-renew
          </label>
        </li>
      {/each}
    </ul>
  {/if}
</section>

<style>
  .adoption-panel {
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-card);
    padding: 1rem;
    margin-bottom: 1rem;
  }

  .panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
  }

  .panel-header h2 {
    margin: 0;
    font-size: 1rem;
  }

  .note {
    font-size: 0.8125rem;
    color: var(--color-text-muted);
    line-height: 1.5;
  }

  .text-muted {
    color: var(--color-text-muted);
    font-weight: 400;
  }

  .toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    margin-bottom: 0.75rem;
  }

  .candidates,
  .results {
    list-style: none;
    padding: 0;
    margin: 0 0 0.75rem;
  }

  .candidate {
    border-top: 1px solid var(--color-border);
    padding: 0.75rem 0;
  }

  .checkbox-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.875rem;
  }

  .domain {
    font-weight: 600;
    color: var(--color-text-heading);
  }

  .summary {
    display: grid;
    grid-template-columns: minmax(10rem, max-content) 1fr;
    gap: 0.25rem 1rem;
    margin: 0.5rem 0 0.5rem 1.5rem;
    font-size: 0.8125rem;
  }

  .summary dt {
    color: var(--color-text-muted);
  }

  .summary dd {
    margin: 0;
    word-break: break-all;
  }

  .mono {
    font-family: var(--mono);
    font-size: 0.75rem;
  }

  .warning {
    margin: 0.5rem 0 0.5rem 1.5rem;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-orange);
    background: var(--color-orange-subtle);
    color: var(--color-orange);
    border-radius: 0.375rem;
    font-size: 0.8125rem;
  }

  .results li {
    padding: 0.375rem 0.5rem;
    font-size: 0.8125rem;
    color: var(--color-red);
  }

  .results li.ok {
    color: var(--color-green);
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

  .btn-cancel {
    background: var(--color-bg-input);
    color: var(--color-text);
  }

  .btn-cancel:hover {
    background: var(--color-bg-hover);
  }
</style>
