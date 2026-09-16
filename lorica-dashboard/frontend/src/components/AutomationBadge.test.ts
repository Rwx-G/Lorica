import { render, screen } from '@testing-library/svelte';
import { describe, it, expect } from 'vitest';
import AutomationBadge from './AutomationBadge.svelte';

describe('AutomationBadge', () => {
  it('reads automation plus the environment name, with the owner in the tooltip', () => {
    render(AutomationBadge, { props: { managedBy: { kind: 'automation', environment: 'pr-42' } } });
    const badge = screen.getByTitle('Managed by the automation API for environment "pr-42"');
    expect(badge).toHaveTextContent('automation');
    expect(badge).toHaveTextContent('pr-42');
  });
});
