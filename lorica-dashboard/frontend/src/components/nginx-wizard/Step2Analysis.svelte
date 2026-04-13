<script lang="ts">
  import {
    LORICA_HANDLED_DIRECTIVES,
    type NginxParseResult,
    type LoricaRouteImport,
  } from '../../lib/nginx-parser';
  import { LORICA_ANNOTATION } from './maps';
  import type { BackendCheck, CertEntry, ConfigLine, IncludeEntry } from './types';

  interface Props {
    configText: string;
    parseResult: NginxParseResult | null;
    importRoutes: LoricaRouteImport[];
    unresolvedIncludes: IncludeEntry[];
    certEntries: CertEntry[];
    backendChecks: BackendCheck[];
    tlsSkipVerifyAddressesPreview: Set<string>;
    hasBlockingErrors: boolean;
    onReparse: () => void;
    onBack: () => void;
    onContinue: () => void;
  }

  let {
    configText,
    parseResult,
    importRoutes,
    unresolvedIncludes = $bindable(),
    certEntries = $bindable(),
    backendChecks = $bindable(),
    tlsSkipVerifyAddressesPreview,
    hasBlockingErrors,
    onReparse,
    onBack,
    onContinue,
  }: Props = $props();

  // Diagnostics grouped by level.
  let diagnostics = $derived(parseResult?.diagnostics ?? []);
  let errors = $derived(diagnostics.filter((d) => d.level === 'error' && d.directive !== 'include'));
  let warnings = $derived(diagnostics.filter((d) => d.level === 'warning'));
  let infos = $derived(diagnostics.filter((d) => d.level === 'info'));

  function getAnnotation(line: string): { text: string; type: 'mapped' | 'handled' | 'none' } {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed === '{' || trimmed === '}') {
      return { text: '', type: 'none' };
    }
    // Extract directive name.
    const spaceIdx = trimmed.indexOf(' ');
    const tabIdx = trimmed.indexOf('\t');
    const sepIdx = spaceIdx === -1 ? tabIdx : tabIdx === -1 ? spaceIdx : Math.min(spaceIdx, tabIdx);
    const directive = sepIdx === -1 ? trimmed.replace(/;$/, '') : trimmed.substring(0, sepIdx);

    // Check if it maps to a Lorica parameter (blue).
    for (const [dir, loricaParam] of Object.entries(LORICA_ANNOTATION)) {
      if (directive === dir) {
        return { text: loricaParam, type: 'mapped' };
      }
    }
    // Check if Lorica handles it internally (gray).
    const handled = LORICA_HANDLED_DIRECTIVES[directive];
    if (handled) {
      return { text: handled, type: 'handled' };
    }
    return { text: '', type: 'none' };
  }

  // Build the resolved config text with include replacements shown.
  let resolvedConfigLines: ConfigLine[] = $derived.by(() => {
    if (!configText.trim()) return [];
    const includeMap = new Map(unresolvedIncludes.map((inc) => [inc.path, inc.content]));
    const lines = configText.split('\n');
    const result: ConfigLine[] = [];

    function pushLine(text: string, kind: 'normal' | 'replaced' = 'normal') {
      const ann = getAnnotation(text);
      result.push({ text, annotation: ann.text, annotationType: ann.type, kind });
    }

    for (const line of lines) {
      const includeMatch = line.match(/^\s*include\s+(.+?)\s*;/);
      if (includeMatch) {
        const path = includeMatch[1];
        const content = includeMap.get(path);
        if (content?.trim()) {
          result.push({ text: `# include ${path} -> resolved:`, annotation: '', annotationType: 'none', kind: 'replaced' });
          for (const subLine of content.split('\n')) {
            pushLine(subLine);
          }
          continue;
        }
      }
      pushLine(line);
    }
    return result;
  });
</script>

<div class="step-content">
  <h3>Analysis results</h3>

  <!-- Unresolved includes -->
  {#if unresolvedIncludes.length > 0}
    <div class="section">
      <h4>Unresolved includes</h4>
      <p class="step-hint">Paste the content of each included file to resolve them, then click "Re-parse".</p>
      {#each unresolvedIncludes as inc, i}
        <div class="include-entry">
          <label class="include-label" for="nginx-import-include-{i}">
            <span class="badge badge-error">include</span>
            <code>{inc.path}</code> (line {inc.line})
          </label>
          <div class="include-cmd">
            <code>{inc.path.includes('letsencrypt') || inc.path.includes('/etc/ssl') ? 'sudo ' : ''}cat {inc.path}</code>
          </div>
          <textarea
            id="nginx-import-include-{i}"
            class="include-textarea"
            bind:value={unresolvedIncludes[i].content}
            placeholder="Paste file contents here..."
            rows="6"
            spellcheck="false"
          ></textarea>
        </div>
      {/each}
      <button class="btn btn-secondary" onclick={onReparse}>Re-parse</button>
    </div>
  {/if}

  <!-- TLS certificates -->
  {#if certEntries.length > 0}
    <div class="section">
      <h4>TLS certificates</h4>
      {#each certEntries as cert, i}
        <div class="cert-import-entry">
          <label class="include-label" for="nginx-import-cert-mode-acme-{i}">
            <span class="badge badge-tls">TLS</span>
            <code>{cert.hostname}{cert.aliases.length > 0 ? `, ${cert.aliases.join(', ')}` : ''}</code>
          </label>
          <div class="cert-mode-toggle">
            <button id="nginx-import-cert-mode-acme-{i}" class="cert-mode-btn" class:active={cert.mode === 'acme'} onclick={() => { certEntries[i].mode = 'acme'; certEntries = [...certEntries]; }}>ACME (Let's Encrypt)</button>
            <button class="cert-mode-btn" class:active={cert.mode === 'import'} onclick={() => { certEntries[i].mode = 'import'; certEntries = [...certEntries]; }}>Import PEM</button>
            <button class="cert-mode-btn" class:active={cert.mode === 'skip'} onclick={() => { certEntries[i].mode = 'skip'; certEntries = [...certEntries]; }}>Skip</button>
          </div>
          {#if cert.mode === 'acme'}
            <p class="step-hint">Certificate will be provisioned automatically via Let's Encrypt HTTP-01. Ensure DNS for {cert.hostname}{cert.aliases.length > 0 ? ` and ${cert.aliases.join(', ')}` : ''} points to this Lorica server on port 80.</p>
          {:else if cert.mode === 'import'}
            <div class="cert-import-row">
              <div class="cert-import-col">
                <span class="cert-import-label">Certificate (fullchain.pem)</span>
                <div class="include-cmd"><code>sudo cat {cert.certPath}</code></div>
                <textarea
                  class="include-textarea"
                  bind:value={certEntries[i].certContent}
                  placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                  rows="4"
                  spellcheck="false"
                ></textarea>
              </div>
              <div class="cert-import-col">
                <span class="cert-import-label">Private key (privkey.pem)</span>
                <div class="include-cmd"><code>sudo cat {cert.keyPath}</code></div>
                <textarea
                  class="include-textarea"
                  bind:value={certEntries[i].keyContent}
                  placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
                  rows="4"
                  spellcheck="false"
                ></textarea>
              </div>
            </div>
          {:else}
            <p class="step-hint">No certificate will be created. You can configure it later in the Certificates page.</p>
          {/if}
        </div>
      {/each}
    </div>
  {/if}

  <!-- Resolved config view -->
  {#if resolvedConfigLines.length > 0}
    <div class="section">
      <h4>Resolved configuration</h4>
      <div class="resolved-config">
        {#each resolvedConfigLines as line, i}
          <div class="resolved-line" class:resolved-replaced={line.kind === 'replaced'}>
            <span class="resolved-lineno">{i + 1}</span>
            <span class="resolved-text">{line.text}</span>
            {#if line.annotation}
              <span class="resolved-annotation" class:annotation-mapped={line.annotationType === 'mapped'} class:annotation-handled={line.annotationType === 'handled'}>{line.annotation}</span>
            {/if}
          </div>
        {/each}
      </div>
    </div>
  {/if}

  <!-- Diagnostics -->
  {#if diagnostics.length > 0}
    <div class="section">
      <h4>Diagnostics</h4>
      <div class="diagnostics-list">
        {#each errors as d}
          <div class="diagnostic diagnostic-error">
            <span class="diag-level">ERROR</span>
            <span class="diag-line">L{d.line}</span>
            <span class="diag-msg">{d.message}</span>
          </div>
        {/each}
        {#each warnings as d}
          <div class="diagnostic diagnostic-warning">
            <span class="diag-level">WARN</span>
            <span class="diag-line">L{d.line}</span>
            <span class="diag-msg">{d.message}</span>
          </div>
        {/each}
        {#each infos as d}
          <div class="diagnostic diagnostic-info">
            <span class="diag-level">INFO</span>
            <span class="diag-line">L{d.line}</span>
            <span class="diag-msg">{d.message}</span>
          </div>
        {/each}
      </div>
    </div>
  {/if}

  <!-- Summary -->
  <div class="section">
    <h4>Parsed</h4>
    <div class="summary-row">
      <span>{parseResult?.servers.length ?? 0} server block(s)</span>
      <span>{parseResult?.upstreams.length ?? 0} upstream block(s)</span>
      <span>{importRoutes.length} route(s) to import</span>
    </div>
    {#if importRoutes.length === 0 && errors.length === 0}
      <p class="step-hint" style="margin-top: 0.75rem;">No routes were detected. The parser expects <code>server</code> blocks containing <code>server_name</code> and <code>proxy_pass</code> directives.</p>
    {/if}
  </div>

  <!-- Backend coherence -->
  {#if backendChecks.length > 0}
    <div class="section">
      <h4>Backends</h4>
      <div class="backend-checks">
        {#each backendChecks as check, i}
          <div class="backend-check-row">
            <code class="backend-addr">{check.address}</code>
            {#if check.exists}
              <span class="badge badge-success">Exists in Lorica</span>
            {:else}
              <label class="backend-create-label">
                <input type="checkbox" bind:checked={backendChecks[i].willCreate} />
                <span class="badge badge-create">Will be created</span>
              </label>
            {/if}
            {#if tlsSkipVerifyAddressesPreview.has(check.address)}
              <span class="badge badge-tls">TLS skip verify</span>
            {/if}
          </div>
        {/each}
      </div>
    </div>
  {/if}

  <div class="step-actions">
    <button class="btn btn-ghost" onclick={onBack}>Back</button>
    <button
      class="btn btn-primary"
      disabled={hasBlockingErrors || importRoutes.length === 0}
      onclick={onContinue}
    >Continue</button>
  </div>
</div>
