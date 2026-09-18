<script lang="ts">
  import { api, type CaptureRuleResponse, type RouteResponse } from '../../lib/api';
  import {
    CAPTURE_BODY_MAX_BYTES_CAP,
    CAPTURE_MAX_CAPTURES_CAP,
    CAPTURE_RATE_PER_MINUTE_CAP,
    CAPTURE_TTL_SECONDS_CAP,
    captureFormFromRule,
    emptyCaptureForm,
    expiresAtFrom,
    hasEmitCondition,
    toCaptureRuleRequest,
    validateCaptureForm,
  } from '../../lib/capture';
  import { showToast } from '../../lib/toast';

  interface Props {
    routes: RouteResponse[];
    /** The rule being edited, or `null` for a new one. */
    editing: CaptureRuleResponse | null;
    onsaved: () => void;
    oncancel: () => void;
  }

  let { routes, editing, onsaved, oncancel }: Props = $props();

  // The form is seeded once, from the rule being edited or from the
  // first route; later prop changes must not reset what the operator
  // typed, which is why this is a function call and not a `$derived`.
  function initialForm() {
    return editing ? captureFormFromRule(editing) : emptyCaptureForm(routes[0]?.id ?? '');
  }

  let form = $state(initialForm());
  let formError = $state('');
  let submitting = $state(false);

  // The server anchors `expires_at` on the rule's creation, never on
  // the edit, so an edited rule's preview anchors there too; a new
  // rule's anchor is the moment the form opened.
  const openedAt = new Date();
  const anchor = $derived(editing ? new Date(editing.created_at) : openedAt);
  const expiresAt = $derived(expiresAtFrom(anchor, form.ttlSeconds));
  const conditioned = $derived(hasEmitCondition(form));

  async function handleSubmit() {
    const err = validateCaptureForm(form);
    if (err) {
      formError = err;
      return;
    }
    submitting = true;
    formError = '';
    const body = toCaptureRuleRequest(form);
    const res = editing
      ? await api.updateCaptureRule(editing.id, body)
      : await api.createCaptureRule(body);
    submitting = false;
    if (res.error) {
      formError = res.error.message;
      return;
    }
    showToast(editing ? 'Capture rule updated' : 'Capture rule armed', 'success');
    onsaved();
  }
</script>

<div
  class="overlay"
  role="dialog"
  aria-modal="true"
  tabindex="-1"
  onclick={(e) => { if (e.target === e.currentTarget) oncancel(); }}
  onkeydown={(e) => { if (e.key === 'Escape') oncancel(); }}
>
  <div class="modal modal-wide" role="document">
    <h2>{editing ? 'Edit capture rule' : 'New capture rule'}</h2>
    <p class="hint">
      A capture rule records real request and response bodies on one route. It stops on its own at
      its total, its rate throttles it, and its clock disables it; every one of the three is required.
    </p>

    {#if formError}
      <div class="form-error" role="alert">{formError}</div>
    {/if}

    <div class="form-row">
      <div class="form-group">
        <label for="cap-name">Name <span class="required">*</span></label>
        <input id="cap-name" type="text" bind:value={form.name} placeholder="checkout 5xx" />
      </div>
      <div class="form-group">
        <label for="cap-route">Route <span class="required">*</span></label>
        <select id="cap-route" bind:value={form.routeId}>
          <option value="">Pick a route</option>
          {#each routes as r (r.id)}
            <option value={r.id}>{r.hostname}{r.path_prefix}</option>
          {/each}
        </select>
      </div>
    </div>

    <h3 class="section-title">Which requests are considered</h3>
    <p class="hint">Every populated field narrows. Empty means every request on the route.</p>
    <div class="form-row">
      <div class="form-group">
        <label for="cap-cidrs">Source CIDRs (one per line)</label>
        <textarea id="cap-cidrs" rows="2" bind:value={form.sourceCidrs} placeholder="10.0.0.0/8"></textarea>
      </div>
      <div class="form-group">
        <label for="cap-methods">Methods</label>
        <input id="cap-methods" type="text" bind:value={form.methods} placeholder="POST, PUT" />
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label for="cap-prefix">Path prefix</label>
        <input id="cap-prefix" type="text" bind:value={form.pathPrefix} placeholder="/checkout" />
      </div>
      <div class="form-group">
        <label for="cap-regex">Path regex</label>
        <input id="cap-regex" type="text" bind:value={form.pathRegex} placeholder="^/api/v[0-9]+/orders" />
      </div>
    </div>

    <h3 class="section-title">When the exchange is written out</h3>
    <p class="hint">
      Conditions are ORed. The response decides, so a request is buffered first and kept only when
      one of these holds.
    </p>
    <div class="form-group">
      <label class="checkbox-item">
        <input type="checkbox" bind:checked={form.statusServerError} disabled={form.always} />
        Status 5xx
      </label>
      <label class="checkbox-item">
        <input type="checkbox" bind:checked={form.statusClientError} disabled={form.always} />
        Status 4xx (except 499)
      </label>
      <label class="checkbox-item">
        <input type="checkbox" bind:checked={form.statusClientAborted} disabled={form.always} />
        Client aborted (499)
      </label>
      <label class="checkbox-item">
        <input type="checkbox" bind:checked={form.upstreamError} disabled={form.always} />
        Upstream error (no response from the backend)
      </label>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label for="cap-exact">Exact statuses</label>
        <input id="cap-exact" type="text" bind:value={form.statusExact} placeholder="502, 504" disabled={form.always} />
      </div>
      <div class="form-group">
        <label for="cap-latency">Minimum latency (ms)</label>
        <input id="cap-latency" type="number" min="0" bind:value={form.minLatencyMs} disabled={form.always} />
      </div>
    </div>
    <div class="form-group always-block" class:always-armed={form.always}>
      <label class="checkbox-item">
        <input type="checkbox" bind:checked={form.always} disabled={conditioned} />
        Record every request on this route, unconditionally
      </label>
      <p class="hint">
        This is the unbounded rule. With no condition, every matched exchange is written out until
        the total, the rate or the clock stops it. Remove every condition above to enable it.
      </p>
    </div>

    <h3 class="section-title">What is kept</h3>
    <div class="form-row">
      <div class="form-group">
        <label class="checkbox-item">
          <input type="checkbox" bind:checked={form.requestBody} />
          Request body
        </label>
        <label for="cap-req-cap">Request body cap (bytes, max {CAPTURE_BODY_MAX_BYTES_CAP})</label>
        <input id="cap-req-cap" type="number" min="1" max={CAPTURE_BODY_MAX_BYTES_CAP} bind:value={form.requestBodyMaxBytes} />
      </div>
      <div class="form-group">
        <label class="checkbox-item">
          <input type="checkbox" bind:checked={form.responseBody} />
          Response body
        </label>
        <label for="cap-resp-cap">Response body cap (bytes, max {CAPTURE_BODY_MAX_BYTES_CAP})</label>
        <input id="cap-resp-cap" type="number" min="1" max={CAPTURE_BODY_MAX_BYTES_CAP} bind:value={form.responseBodyMaxBytes} />
      </div>
    </div>
    <p class="hint">
      Headers and the request line are always kept. The response body is the upstream's, before any
      rewrite this proxy applied. Bodies are not redacted.
    </p>

    <h3 class="section-title">Budget</h3>
    <div class="form-row">
      <div class="form-group">
        <label for="cap-max">Max captures (1 to {CAPTURE_MAX_CAPTURES_CAP})</label>
        <input id="cap-max" type="number" min="1" max={CAPTURE_MAX_CAPTURES_CAP} bind:value={form.maxCaptures} />
      </div>
      <div class="form-group">
        <label for="cap-rate">Rate per minute (1 to {CAPTURE_RATE_PER_MINUTE_CAP})</label>
        <input id="cap-rate" type="number" min="1" max={CAPTURE_RATE_PER_MINUTE_CAP} bind:value={form.ratePerMinute} />
      </div>
      <div class="form-group">
        <label for="cap-ttl">TTL (seconds, max {CAPTURE_TTL_SECONDS_CAP})</label>
        <input id="cap-ttl" type="number" min="1" max={CAPTURE_TTL_SECONDS_CAP} bind:value={form.ttlSeconds} />
        <p class="hint expires-preview" data-testid="expires-preview">
          Expires at {expiresAt.toLocaleString()}
          {#if editing}(anchored on the rule's creation){/if}
        </p>
      </div>
    </div>
    <p class="hint">
      The total and the rate are counted per process: under --workers each worker has its own. The
      expiry is the one bound every node agrees on.
    </p>

    <h3 class="section-title">Output and redaction</h3>
    <div class="form-row">
      <div class="form-group">
        <label for="cap-dir">Directory (absolute, must exist, optional)</label>
        <input id="cap-dir" type="text" bind:value={form.outputDir} placeholder="/var/lib/lorica/captures" />
      </div>
      <div class="form-group">
        <label for="cap-dir-bytes">Directory size budget (bytes, optional)</label>
        <input id="cap-dir-bytes" type="number" min="1" bind:value={form.maxDirBytes} />
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label for="cap-redact-headers">Extra redacted headers (one per line)</label>
        <textarea id="cap-redact-headers" rows="2" bind:value={form.redactHeaders} placeholder="X-Api-Key"></textarea>
      </div>
      <div class="form-group">
        <label for="cap-redact-query">Redacted query parameters (one per line)</label>
        <textarea id="cap-redact-query" rows="2" bind:value={form.redactQuery} placeholder="token"></textarea>
      </div>
    </div>
    <p class="hint">
      Authorization, Proxy-Authorization, Cookie and Set-Cookie are always redacted; a rule can only
      add names.
    </p>

    {#if editing}
      <div class="form-group">
        <label class="checkbox-item">
          <input type="checkbox" bind:checked={form.enabled} />
          Enabled
        </label>
      </div>
    {/if}

    <div class="form-actions">
      <button class="btn btn-cancel" onclick={oncancel}>Cancel</button>
      <button class="btn btn-primary" onclick={handleSubmit} disabled={submitting}>
        {submitting ? 'Saving...' : editing ? 'Update' : 'Arm rule'}
      </button>
    </div>
  </div>
</div>

<style>
  .modal-wide { max-width: 820px; max-height: 90vh; overflow-y: auto; }
  .section-title { font-size: var(--text-md); font-weight: 600; margin: var(--space-4) 0 var(--space-1); color: var(--color-text-heading); }
  .always-block { border: 1px solid var(--color-border); border-radius: var(--radius-md); padding: var(--space-3); }
  .always-armed { border-color: var(--color-orange); }
  .expires-preview { margin-top: var(--space-1); }
  textarea { width: 100%; font-family: var(--mono); font-size: var(--text-sm); }
</style>
