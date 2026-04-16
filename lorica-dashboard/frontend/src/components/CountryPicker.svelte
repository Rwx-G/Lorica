<script lang="ts">
  import { onMount } from 'svelte';
  // Vite ships the SVG as a URL at build time (?url suffix). The
  // map is bundled INTO the dashboard asset pipeline so the .deb
  // carries it by default — no runtime fetch, no CDN.
  import worldMapUrl from '../assets/world-map.svg?url';
  import {
    parseCountryValue,
    findIsoCodeInAncestry,
    toggleCountry,
  } from '../lib/country-picker';

  interface Props {
    /// Bound value: comma-separated list of ISO 3166-1 alpha-2
    /// codes (upper-case). The picker keeps this in sync both ways.
    value: string;
    /// Optional label shown above the picker.
    label?: string;
    /// Optional hint shown below.
    hint?: string;
  }

  let { value = $bindable(''), label = '', hint = '' }: Props = $props();

  // Parse the comma-separated value into a Set of upper-case codes
  // for O(1) membership tests. Kept in sync with `value` via effects
  // so parent updates propagate back into the map highlight.
  let selected = $state<Set<string>>(new Set());
  let svgContainer: HTMLDivElement | undefined = $state();
  let ready = $state(false);
  let loadError = $state('');

  // Search / filter input that lets the operator type a country
  // name to highlight it on the map (so the picker is usable even
  // when the country is tiny like Malta).
  let search = $state('');

  // Externally-driven value changes -> rebuild selection Set.
  $effect(() => {
    const incoming = parseCountryValue(value);
    if (selected.size !== incoming.size ||
        ![...selected].every((c) => incoming.has(c))) {
      selected = incoming;
      applyHighlights();
    }
  });

  function applyHighlights() {
    if (!svgContainer) return;
    const svg = svgContainer.querySelector('svg');
    if (!svg) return;
    // Toggle a data attribute + CSS class on each country path.
    svg.querySelectorAll('path[id], g[id]').forEach((el) => {
      const id = el.getAttribute('id') ?? '';
      // Wikimedia IDs are lowercase; we compare case-insensitively.
      const iso = id.toUpperCase();
      if (iso.length === 2 && selected.has(iso)) {
        el.classList.add('country-selected');
      } else {
        el.classList.remove('country-selected');
      }
    });
  }

  function handleClick(e: MouseEvent) {
    const target = e.target as SVGElement;
    const iso = findIsoCodeInAncestry(target, svgContainer ?? null);
    if (!iso) return;
    const { next, csv } = toggleCountry(selected, iso);
    selected = next;
    value = csv;
    applyHighlights();
  }

  function removeChip(iso: string) {
    const { next, csv } = toggleCountry(selected, iso);
    selected = next;
    value = csv;
    applyHighlights();
  }

  function clearAll() {
    selected = new Set();
    value = '';
    applyHighlights();
  }

  onMount(async () => {
    try {
      const resp = await fetch(worldMapUrl);
      if (!resp.ok) {
        loadError = `map asset missing (HTTP ${resp.status})`;
        return;
      }
      const svgText = await resp.text();
      if (svgContainer) {
        svgContainer.innerHTML = svgText;
        // Make the SVG fill its container; strip fixed
        // width/height that Wikimedia hardcodes.
        const svg = svgContainer.querySelector('svg');
        if (svg) {
          svg.removeAttribute('width');
          svg.removeAttribute('height');
          svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
          svg.addEventListener('click', handleClick as EventListener);
        }
        applyHighlights();
      }
      ready = true;
    } catch (err: unknown) {
      loadError = `map load failed: ${err instanceof Error ? err.message : String(err)}`;
    }
  });

  // Re-apply highlights whenever search changes so tiny/hidden
  // countries get a temporary outline.
  function searchMatches(iso: string): boolean {
    if (!search.trim()) return false;
    const q = search.trim().toUpperCase();
    return iso.includes(q);
  }

  $effect(() => {
    if (!svgContainer) return;
    const svg = svgContainer.querySelector('svg');
    if (!svg) return;
    svg.querySelectorAll('path[id], g[id]').forEach((el) => {
      const iso = (el.getAttribute('id') ?? '').toUpperCase();
      if (iso.length === 2 && searchMatches(iso)) {
        el.classList.add('country-search-hit');
      } else {
        el.classList.remove('country-search-hit');
      }
    });
  });
</script>

<div class="country-picker">
  {#if label}<label>{label}</label>{/if}

  {#if loadError}
    <!-- Fallback: plain text input when the SVG asset is missing
         (e.g. operator stripped it for CC-BY-SA compliance). The
         picker stays usable, just without the map. -->
    <div class="fallback">
      <p class="warn">World-map asset unavailable ({loadError}). Falling back to CSV input.</p>
      <input
        type="text"
        bind:value
        placeholder="e.g. FR, DE, US (comma-separated, ISO 3166-1 alpha-2)"
        autocomplete="off"
      />
    </div>
  {:else}
    <div class="controls">
      <input
        type="text"
        class="search"
        bind:value={search}
        placeholder="Search ISO code (e.g. FR)"
        autocomplete="off"
      />
      <button type="button" class="clear" onclick={clearAll} disabled={selected.size === 0}>
        Clear all
      </button>
    </div>

    <div
      class="map-container"
      bind:this={svgContainer}
      role="application"
      aria-label="World map country picker - click a country to select it"
    >
      {#if !ready}<p class="loading">Loading map...</p>{/if}
    </div>

    <div class="chips">
      {#if selected.size === 0}
        <span class="muted">No country selected — click on the map to add.</span>
      {:else}
        {#each [...selected].sort() as iso (iso)}
          <button type="button" class="chip" onclick={() => removeChip(iso)} title="Click to remove">
            {iso} <span aria-hidden="true">×</span>
          </button>
        {/each}
      {/if}
    </div>

    <!-- CSV input kept as an advanced escape hatch: an operator
         pasting a long country list will find this faster than
         clicking 40 times on the map. -->
    <details class="advanced">
      <summary>Advanced: paste CSV</summary>
      <input
        type="text"
        bind:value
        placeholder="e.g. FR, DE, US"
        autocomplete="off"
      />
    </details>
  {/if}

  {#if hint}<span class="hint">{hint}</span>{/if}
</div>

<style>
  .country-picker {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  label {
    font-weight: 500;
  }
  .controls {
    display: flex;
    gap: 0.5rem;
  }
  .search {
    flex: 1;
    padding: 0.4rem 0.6rem;
    border: 1px solid var(--color-border, #ccc);
    border-radius: 4px;
  }
  .clear {
    padding: 0.4rem 0.8rem;
    background: transparent;
    border: 1px solid var(--color-border, #ccc);
    border-radius: 4px;
    cursor: pointer;
  }
  .clear:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .map-container {
    width: 100%;
    max-height: 500px;
    overflow: hidden;
    border: 1px solid var(--color-border, #ddd);
    border-radius: 6px;
    background: var(--color-bg-subtle, #f8f8f8);
  }
  .map-container :global(svg) {
    width: 100%;
    height: auto;
    max-height: 500px;
    display: block;
  }
  .map-container :global(path),
  .map-container :global(g[id]) {
    cursor: pointer;
    transition: fill 0.1s;
  }
  .map-container :global(path:hover),
  .map-container :global(g[id]:hover path) {
    fill: var(--color-primary-muted, #a5bfe5) !important;
  }
  .map-container :global(.country-selected),
  .map-container :global(.country-selected path) {
    fill: var(--color-primary, #0b57d0) !important;
    stroke: var(--color-primary, #0b57d0) !important;
    stroke-width: 0.5;
  }
  .map-container :global(.country-search-hit),
  .map-container :global(.country-search-hit path) {
    stroke: var(--color-warning, #ef6c00) !important;
    stroke-width: 2 !important;
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 0.25rem;
    min-height: 2rem;
    padding: 0.25rem 0;
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    padding: 0.2rem 0.5rem;
    background: var(--color-primary, #0b57d0);
    color: #fff;
    border: none;
    border-radius: 12px;
    font-size: 0.8em;
    font-weight: 500;
    cursor: pointer;
  }
  .chip:hover {
    background: var(--color-primary-dark, #0946a8);
  }
  .muted {
    color: var(--color-text-muted, #666);
    font-size: 0.85em;
    font-style: italic;
  }
  .advanced {
    margin-top: 0.5rem;
    font-size: 0.85em;
  }
  .advanced input {
    width: 100%;
    margin-top: 0.3rem;
    padding: 0.3rem 0.5rem;
    border: 1px solid var(--color-border, #ccc);
    border-radius: 4px;
  }
  .fallback .warn {
    color: var(--color-warning, #b85c00);
    font-size: 0.85em;
    margin: 0 0 0.3rem;
  }
  .fallback input {
    width: 100%;
    padding: 0.4rem 0.6rem;
    border: 1px solid var(--color-border, #ccc);
    border-radius: 4px;
  }
  .hint {
    color: var(--color-text-muted, #666);
    font-size: 0.8em;
  }
  .loading {
    padding: 2rem;
    text-align: center;
    color: var(--color-text-muted, #666);
  }
</style>
