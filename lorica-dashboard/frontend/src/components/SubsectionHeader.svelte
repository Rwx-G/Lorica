<script lang="ts">
  /**
   * Palette colour for the subsection header top-border + background
   * tint. Pick a different value for each subsection inside a given
   * tab so the sections are visually distinct.
   */
  type Accent = 'blue' | 'green' | 'purple' | 'cyan' | 'red' | 'orange' | 'slate' | 'pink' | 'teal' | 'amber';

  interface Props {
    title: string;
    description?: string;
    onhelp?: () => void;
    accent?: Accent;
    /**
     * Evaluation-order badge shown on the right of the header (big
     * digit, larger than the ? button). Use a number for ordered
     * stages or a glyph (e.g. "∥") for parallel/orthogonal stages.
     * Omit when the section is not part of a pipeline.
     */
    order?: number | string;
    /** Tooltip for the order badge (e.g. "Evaluated 1st of 4"). */
    orderLabel?: string;
  }

  let { title, description, onhelp, accent = 'blue', order, orderLabel }: Props = $props();
</script>

<header class="subsection-header" data-accent={accent}>
  <div class="title-row">
    <h3>{title}</h3>
    {#if onhelp}
      <button type="button" class="help-btn" onclick={onhelp} aria-label="Help on {title}" title="What is this section?">
        ?
      </button>
    {/if}
    {#if order !== undefined}
      <span class="order-badge" title={orderLabel} aria-label={orderLabel ?? `Step ${order}`}>
        {order}
      </span>
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
    border-top: 4px solid transparent;
    margin-bottom: 0;
  }

  /* Palette: 4 px top border + ~8 % alpha tinted background. All
     accents produce comparable contrast in light + dark themes. */
  .subsection-header[data-accent='blue']   { border-top-color: #3b82f6; background: rgba(59,  130, 246, 0.08); }
  .subsection-header[data-accent='green']  { border-top-color: #10b981; background: rgba(16,  185, 129, 0.08); }
  .subsection-header[data-accent='purple'] { border-top-color: #8b5cf6; background: rgba(139, 92,  246, 0.08); }
  .subsection-header[data-accent='cyan']   { border-top-color: #06b6d4; background: rgba(6,   182, 212, 0.08); }
  .subsection-header[data-accent='red']    { border-top-color: #ef4444; background: rgba(239, 68,  68,  0.08); }
  .subsection-header[data-accent='orange'] { border-top-color: #f59e0b; background: rgba(245, 158, 11,  0.08); }
  .subsection-header[data-accent='slate']  { border-top-color: #64748b; background: rgba(100, 116, 139, 0.08); }
  .subsection-header[data-accent='pink']   { border-top-color: #ec4899; background: rgba(236, 72,  153, 0.08); }
  .subsection-header[data-accent='teal']   { border-top-color: #14b8a6; background: rgba(20,  184, 166, 0.08); }
  .subsection-header[data-accent='amber']  { border-top-color: #d97706; background: rgba(217, 119, 6,   0.08); }

  .title-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .order-badge {
    margin-left: auto;
    min-width: 1.75rem;
    height: 1.75rem;
    padding: 0 0.5rem;
    border-radius: 9999px;
    background: var(--color-bg-card);
    border: 1.5px solid var(--color-border);
    color: var(--color-text-heading);
    font-size: 1rem;
    font-weight: 700;
    line-height: 1;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-variant-numeric: tabular-nums;
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
