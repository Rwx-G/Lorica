<script lang="ts">
  interface Props {
    theme: 'dark' | 'light';
    expanded: boolean;
    toggleSection: () => void;
    onToggleTheme: () => void | Promise<void>;
  }

  let { theme, expanded, toggleSection, onToggleTheme }: Props = $props();
</script>

<section class="settings-section">
  <button class="settings-collapsible-header" class:open={expanded} onclick={toggleSection}>
    <h2>Appearance</h2>
    <span class="settings-chevron" class:expanded></span>
  </button>
  {#if expanded}
    <div class="settings-section-body">
      <p class="settings-hint">Current theme: {theme}.</p>
      <div class="settings-dialog-actions">
        <button class="btn btn-secondary" onclick={onToggleTheme}>
          {theme === 'dark' ? 'Switch to Light' : 'Switch to Dark'}
        </button>
      </div>
    </div>
  {/if}
</section>
