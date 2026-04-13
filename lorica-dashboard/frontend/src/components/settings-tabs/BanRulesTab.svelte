<script lang="ts">
  interface Props {
    expanded: boolean;
    toggleSection: () => void;
  }

  let { expanded, toggleSection }: Props = $props();
</script>

<section class="settings-section">
  <button class="settings-collapsible-header" class:open={expanded} onclick={toggleSection}>
    <h2>Ban Rules</h2>
    <span class="settings-chevron" class:expanded></span>
  </button>
  {#if expanded}
    <div class="settings-section-body">
      <p class="settings-hint">Ban rules (slowloris protection, auto-ban threshold and duration) are configured per-route in the Routes page under Advanced Configuration &gt; Protection.</p>
    </div>
  {/if}
</section>
