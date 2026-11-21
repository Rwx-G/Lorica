<script lang="ts">
  import type { CertificateResponse, StreamProtocol } from '../../lib/api';
  import { emptyRule, scalarsOn, type StreamDraft, type StreamField } from '../../lib/stream-form';
  import ScalarFields from './ScalarFields.svelte';

  interface Props {
    draft: StreamDraft;
    fields: ReadonlySet<StreamField>;
    protocol: StreamProtocol;
    creating: boolean;
    certificates: CertificateResponse[];
  }

  let { draft = $bindable(), fields, protocol, creating, certificates }: Props = $props();

  const KEYS = scalarsOn('tls');

  function addRule() {
    draft.rules = [...draft.rules, emptyRule()];
  }

  function removeRule(index: number) {
    draft.rules = draft.rules.filter((_, i) => i !== index);
  }

  function toggleCertificate(id: string) {
    draft.certificateIds = draft.certificateIds.includes(id)
      ? draft.certificateIds.filter((c) => c !== id)
      : [...draft.certificateIds, id];
  }
</script>

<div class="tab-content">
  <ScalarFields bind:draft keys={KEYS} {fields} {protocol} {creating} />

  {#if fields.has('match_rules')}
    <h3 class="subsection-title">Rules</h3>
    <p class="hint">
      A ClientHello is routed by the server name it carries and the protocols it
      offers; the backends of each rule are on the Backends tab. No rule
      matching closes the connection before any byte is forwarded.
    </p>
    {#each draft.rules as rule, i (i)}
      <section class="rule" aria-label="Rule {rule.name || i + 1}">
        <div class="form-row">
          <div class="form-group">
            <label for="stream-rule-{i}-name">Rule name</label>
            <input id="stream-rule-{i}-name" type="text" bind:value={draft.rules[i].name} />
          </div>
          <div class="form-group">
            <label for="stream-rule-{i}-kind">Matches</label>
            <select id="stream-rule-{i}-kind" bind:value={draft.rules[i].kind}>
              <option value="tls">Server names</option>
              <option value="no_sni">Clients naming no server</option>
            </select>
          </div>
        </div>
        {#if rule.kind === 'tls'}
          <div class="form-group">
            <label for="stream-rule-{i}-names">Server names</label>
            <textarea id="stream-rule-{i}-names" rows="2" placeholder="db.example.com" bind:value={draft.rules[i].server_names}></textarea>
            <span class="hint">One per line, exact or wildcard (*.example.com).</span>
          </div>
        {/if}
        <div class="form-group">
          <label for="stream-rule-{i}-alpn">ALPN</label>
          <textarea id="stream-rule-{i}-alpn" rows="1" placeholder="any offer" bind:value={draft.rules[i].alpn}></textarea>
        </div>
        <button type="button" class="btn btn-secondary btn-sm" onclick={() => removeRule(i)}>Remove rule</button>
      </section>
    {/each}
    <button type="button" class="btn btn-secondary" onclick={addRule}>+ Add rule</button>
  {/if}

  {#if fields.has('tls_terminate')}
    <h3 class="subsection-title">Termination</h3>
    <div class="form-group">
      <span class="group-label">Certificates</span>
      {#if certificates.length === 0}
        <p class="hint">No certificate is stored yet.</p>
      {/if}
      {#each certificates as cert (cert.id)}
        <label class="checkbox-item">
          <input type="checkbox" checked={draft.certificateIds.includes(cert.id)} onchange={() => toggleCertificate(cert.id)} />
          {cert.domain}
        </label>
      {/each}
      <span class="hint">Every exact server name of a rule must be served by one of them; the server names the rule it cannot serve.</span>
    </div>
    <label class="checkbox-item">
      <input type="checkbox" bind:checked={draft.clientAuth} />
      Verify client certificates
    </label>
    {#if draft.clientAuth}
      <div class="form-group">
        <label for="stream-client-ca">Client CA bundle (PEM)</label>
        <textarea id="stream-client-ca" rows="4" bind:value={draft.clientAuthCaPem}></textarea>
      </div>
      <label class="checkbox-item">
        <input type="checkbox" bind:checked={draft.clientAuthRequired} />
        Require a client certificate
      </label>
      <div class="form-group">
        <label for="stream-client-orgs">Allowed organizations (O=)</label>
        <textarea id="stream-client-orgs" rows="2" placeholder="any" bind:value={draft.clientAuthOrganizations}></textarea>
      </div>
    {/if}
  {/if}

  {#if fields.has('upstream_tls')}
    <h3 class="subsection-title">TLS to the backends</h3>
    <label class="checkbox-item">
      <input type="checkbox" bind:checked={draft.upstreamTls} />
      Open TLS towards the backends
    </label>
    {#if draft.upstreamTls}
      <div class="form-group">
        <label for="stream-upstream-sni">Server name sent and verified</label>
        <select id="stream-upstream-sni" bind:value={draft.upstreamServerName}>
          <option value="">Server default</option>
          <option value="backend_address">The backend's host</option>
          {#if fields.has('tls_terminate')}<option value="client">The client's server name</option>{/if}
          <option value="fixed">A fixed name</option>
        </select>
      </div>
      {#if draft.upstreamServerName === 'fixed'}
        <div class="form-group">
          <label for="stream-upstream-name">Fixed name</label>
          <input id="stream-upstream-name" type="text" bind:value={draft.upstreamFixedName} />
        </div>
      {/if}
      <div class="form-group">
        <label for="stream-upstream-ca">CA bundle (PEM)</label>
        <textarea id="stream-upstream-ca" rows="3" placeholder="public roots" bind:value={draft.upstreamCaPem}></textarea>
      </div>
      <div class="form-group">
        <label for="stream-upstream-cert">Client certificate presented</label>
        <select id="stream-upstream-cert" bind:value={draft.upstreamClientCertificateId}>
          <option value="">None</option>
          {#each certificates as cert (cert.id)}
            <option value={cert.id}>{cert.domain}</option>
          {/each}
        </select>
      </div>
      <div class="form-group">
        <label for="stream-upstream-alpn">ALPN offered</label>
        <textarea id="stream-upstream-alpn" rows="1" placeholder="none" bind:value={draft.upstreamAlpn}></textarea>
      </div>
      <label class="checkbox-item">
        <input type="checkbox" bind:checked={draft.upstreamSkipVerify} />
        Skip backend certificate verification
      </label>
      <span class="hint">Accepts any backend certificate, so anyone on the path to the backend can read and change the traffic.</span>
    {/if}
  {/if}
</div>

<style>
  .subsection-title {
    margin: var(--space-4) 0 var(--space-2);
    font-size: var(--text-md);
    color: var(--color-text-heading);
  }
  .group-label {
    display: block;
    font-size: var(--text-base);
    font-weight: 500;
    color: var(--color-text-muted);
    margin-bottom: var(--space-1);
  }
  .rule {
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    padding: var(--space-3) var(--space-4);
    margin-bottom: var(--space-3);
  }
  .btn-sm {
    padding: var(--space-1) var(--space-2);
    font-size: var(--text-sm);
  }
</style>
