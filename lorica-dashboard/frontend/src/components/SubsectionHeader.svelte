<script lang="ts">
  interface Props {
    title: string;
    description?: string;
    onhelp?: () => void;
    accent?: 'identity' | 'routing' | 'transform' | 'cache' | 'security' | 'protection' | 'upstream' | 'behavior';
  }

  let { title, description, onhelp, accent = 'identity' }: Props = $props();
</script>

<header class="subsection-header" data-accent={accent}>
  <div class="title-row">
    <h3>{title}</h3>
    {#if onhelp}
      <button type="button" class="help-btn" onclick={onhelp} aria-label="Help on {title}" title="What is this section?">
        ?
      </button>
    {/if}
  </div>
  {#if description}
    <p class="description">{description}</p>
  {/if}
</header>

<style>
  .subsection-header {
    position: relative;
    padding: 0.875rem 1rem 0.75rem;
    border-radius: 0.5rem 0.5rem 0 0;
    border: 1px solid var(--color-border);
    border-bottom: none;
    /* 4px top accent bar per section family. Keeps the left edge
       free so the per-field `modified` left border (primary color)
       does not collide visually with the section accent. */
    border-top: 4px solid transparent;
    margin-bottom: 0;
  }

  /* Section accents: top border colour + tinted background distinct
     from `--color-bg-input` (used by form inputs) so the header
     reads as a separate surface. ~8 % opacity keeps the text
     contrast high in both light and dark themes. */
  .subsection-header[data-accent='identity']   { border-top-color: var(--color-primary, #3b82f6); background: rgba(59, 130, 246, 0.08); }
  .subsection-header[data-accent='routing']    { border-top-color: var(--color-green, #10b981);   background: rgba(16, 185, 129, 0.08); }
  .subsection-header[data-accent='transform']  { border-top-color: #8b5cf6;                        background: rgba(139, 92, 246, 0.08); }
  .subsection-header[data-accent='cache']      { border-top-color: #06b6d4;                        background: rgba(6, 182, 212, 0.08); }
  .subsection-header[data-accent='security']   { border-top-color: var(--color-red, #ef4444);      background: rgba(239, 68, 68, 0.08); }
  .subsection-header[data-accent='protection'] { border-top-color: var(--color-orange, #f59e0b);   background: rgba(245, 158, 11, 0.08); }
  .subsection-header[data-accent='upstream']   { border-top-color: #64748b;                        background: rgba(100, 116, 139, 0.08); }
  .subsection-header[data-accent='behavior']   { border-top-color: #ec4899;                        background: rgba(236, 72, 153, 0.08); }

  .title-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  h3 {
    margin: 0;
    font-size: 0.875rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--color-text-heading);
  }

  .help-btn {
    flex-shrink: 0;
    width: 1.25rem;
    height: 1.25rem;
    padding: 0;
    border-radius: 9999px;
    border: 1px solid var(--color-border);
    background: var(--color-bg-card);
    color: var(--color-text-muted);
    font-size: 0.75rem;
    font-weight: 700;
    line-height: 1;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .help-btn:hover {
    color: var(--color-primary);
    border-color: var(--color-primary);
  }

  .description {
    margin: 0.25rem 0 0;
    font-size: 0.8125rem;
    color: var(--color-text-muted);
    line-height: 1.4;
  }
</style>
