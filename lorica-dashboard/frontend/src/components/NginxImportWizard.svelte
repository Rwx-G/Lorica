<script lang="ts">
  import { api, type BackendResponse } from '../lib/api';
  import {
    parseNginxConfig,
    convertToLoricaRoutes,
    type NginxParseResult,
    type LoricaRouteImport,
  } from '../lib/nginx-parser';
  import Step1Paste from './nginx-wizard/Step1Paste.svelte';
  import Step2Analysis from './nginx-wizard/Step2Analysis.svelte';
  import Step3Preview from './nginx-wizard/Step3Preview.svelte';
  import Step4Results from './nginx-wizard/Step4Results.svelte';
  import { CHECK_ICON, CLOSE_ICON, WIZARD_STEP_LABELS } from './nginx-wizard/maps';
  import type { ApplyResult, BackendCheck, CertEntry, IncludeEntry } from './nginx-wizard/types';
  import { runImport } from './nginx-wizard/import-pipeline';
  import './nginx-wizard/wizard.css';

  interface Props {
    open: boolean;
    onclose: () => void;
    onimported: () => void;
  }

  let { open, onclose, onimported }: Props = $props();

  // Wizard state
  let step = $state(1);
  let configText = $state('');
  let parseResult = $state<NginxParseResult | null>(null);
  let importRoutes = $state<LoricaRouteImport[]>([]);
  let existingBackends = $state<BackendResponse[]>([]);
  let backendChecks: BackendCheck[] = $state([]);
  let unresolvedIncludes: IncludeEntry[] = $state([]);
  let certEntries: CertEntry[] = $state([]);
  let previewTab = $state(0);
  let applyResults: ApplyResult[] = $state([]);
  let applying = $state(false);

  // Derived: blocking errors (unresolved includes)
  let hasBlockingErrors = $derived(unresolvedIncludes.length > 0);

  // Derived: backend addresses that need TLS skip verify
  let tlsSkipVerifyAddressesPreview = $derived.by(() => {
    const addrs = new Set<string>();
    for (const route of importRoutes) {
      if (route._backendTlsSkipVerify) {
        for (const addr of route.backend_addresses) addrs.add(addr);
      }
    }
    return addrs;
  });

  function escapeRegex(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function reset() {
    step = 1;
    configText = '';
    parseResult = null;
    importRoutes = [];
    existingBackends = [];
    backendChecks = [];
    unresolvedIncludes = [];
    certEntries = [];
    previewTab = 0;
    applyResults = [];
    applying = false;
  }

  function handleClose() {
    reset();
    onclose();
  }

  // Inline-replace include directives with their pasted content.
  function expandIncludes(text: string): string {
    let out = text;
    for (const inc of unresolvedIncludes) {
      if (inc.content.trim()) {
        const pattern = new RegExp(`^\\s*include\\s+${escapeRegex(inc.path)}\\s*;`, 'gm');
        out = out.replace(pattern, inc.content);
      }
    }
    return out;
  }

  // Extract unresolved include diagnostics, deduplicating by path.
  // Optionally preserves previously entered include content (for re-parse).
  function extractUnresolvedIncludes(
    diagnostics: NginxParseResult['diagnostics'],
    previous?: Map<string, string>,
  ): IncludeEntry[] {
    const seen = new Set<string>();
    return diagnostics
      .filter((d) => d.directive === 'include' && d.level === 'error')
      .filter((d) => {
        const path = d.message
          .replace('Unresolved include: ', '')
          .replace('. Paste file contents to resolve.', '');
        if (seen.has(path)) return false;
        seen.add(path);
        return true;
      })
      .map((d) => {
        const path = d.message
          .replace('Unresolved include: ', '')
          .replace('. Paste file contents to resolve.', '');
        return { line: d.line, path, content: previous?.get(path) ?? '' };
      });
  }

  // Recompute backend checks for all routes (including path rule backends).
  function recomputeBackendChecks() {
    const allAddresses = new Set<string>();
    for (const route of importRoutes) {
      for (const addr of route.backend_addresses) allAddresses.add(addr);
      for (const rule of route.path_rules ?? []) {
        for (const addr of rule.backend_addresses ?? []) allAddresses.add(addr);
      }
    }

    backendChecks = Array.from(allAddresses).map((addr) => {
      const existing = existingBackends.find((b) => b.address === addr);
      return {
        address: addr,
        exists: !!existing,
        willCreate: !existing,
        existingId: existing?.id,
      };
    });
  }

  // Step 1 -> Step 2: parse and analyze
  async function parseAndAnalyze() {
    const fullText = expandIncludes(configText);
    parseResult = parseNginxConfig(fullText);
    importRoutes = convertToLoricaRoutes(parseResult);

    unresolvedIncludes = extractUnresolvedIncludes(parseResult.diagnostics);

    // Extract TLS certificate paths (deduplicate by hostname; aliases used as SAN)
    const seenCertHosts = new Set<string>();
    certEntries = [];
    for (const route of importRoutes) {
      if (route._sslCertPath && route._sslKeyPath && !seenCertHosts.has(route.hostname)) {
        seenCertHosts.add(route.hostname);
        certEntries.push({
          hostname: route.hostname,
          aliases: route.hostname_aliases.filter(Boolean),
          certPath: route._sslCertPath,
          keyPath: route._sslKeyPath,
          mode: 'acme',
          certContent: '',
          keyContent: '',
        });
      }
    }

    // Fetch existing backends for coherence check
    const res = await api.listBackends();
    if (res.data) {
      existingBackends = res.data.backends;
    }

    recomputeBackendChecks();
    step = 2;
  }

  // Step 2: re-parse with includes
  function reparseWithIncludes() {
    const fullText = expandIncludes(configText);
    parseResult = parseNginxConfig(fullText);
    importRoutes = convertToLoricaRoutes(parseResult);

    // Update configText with resolved includes so the resolved config view stays accurate
    configText = fullText;

    const oldContentByPath = new Map(unresolvedIncludes.map((inc) => [inc.path, inc.content]));
    unresolvedIncludes = extractUnresolvedIncludes(parseResult.diagnostics, oldContentByPath);
    recomputeBackendChecks();
  }

  function goToPreview() {
    previewTab = 0;
    step = 3;
  }

  // Step 3 -> Step 4: apply
  async function applyImport() {
    applying = true;
    applyResults = await runImport(importRoutes, backendChecks, certEntries);
    applying = false;
    step = 4;
  }

  function handleFinish() {
    const anySuccess = applyResults.some((r) => r.success);
    if (anySuccess) {
      onimported();
    }
    handleClose();
  }
</script>

{#if open}
  <div class="wizard-overlay" role="dialog" aria-modal="true" aria-label="Nginx Import Wizard">
    <div class="wizard-container">
      <!-- Header -->
      <div class="wizard-header">
        <h2>Import from Nginx</h2>
        <button class="wizard-close" onclick={handleClose} aria-label="Close">
          {@html CLOSE_ICON}
        </button>
      </div>

      <!-- Stepper -->
      <div class="stepper">
        {#each WIZARD_STEP_LABELS as label, i}
          {@const stepNum = i + 1}
          <div class="stepper-item" class:active={step === stepNum} class:completed={step > stepNum}>
            <div class="stepper-circle">
              {#if step > stepNum}
                {@html CHECK_ICON}
              {:else}
                {stepNum}
              {/if}
            </div>
            <span class="stepper-label">{label}</span>
          </div>
          {#if i < WIZARD_STEP_LABELS.length - 1}
            <div class="stepper-line" class:completed={step > stepNum}></div>
          {/if}
        {/each}
      </div>

      <!-- Step content -->
      <div class="wizard-body">
        {#if step === 1}
          <Step1Paste bind:configText onCancel={handleClose} onParse={parseAndAnalyze} />
        {:else if step === 2}
          <Step2Analysis
            {configText}
            {parseResult}
            {importRoutes}
            bind:unresolvedIncludes
            bind:certEntries
            bind:backendChecks
            {tlsSkipVerifyAddressesPreview}
            {hasBlockingErrors}
            onReparse={reparseWithIncludes}
            onBack={() => { step = 1; }}
            onContinue={goToPreview}
          />
        {:else if step === 3}
          <Step3Preview
            {importRoutes}
            bind:previewTab
            {applying}
            onBack={() => { step = 2; }}
            onApply={applyImport}
          />
        {:else if step === 4}
          <Step4Results
            {applyResults}
            {certEntries}
            {importRoutes}
            {backendChecks}
            {tlsSkipVerifyAddressesPreview}
            onFinish={handleFinish}
          />
        {/if}
      </div>
    </div>
  </div>
{/if}
