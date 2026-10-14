import { render, screen } from '@testing-library/svelte';
import { describe, it, expect } from 'vitest';
import LogStoreBanner from './LogStoreBanner.svelte';

const MESSAGE = 'Audit trail, access logs and WAF events are not being persisted';

describe('LogStoreBanner', () => {
  it('names the cause while the node is not persisting', () => {
    render(LogStoreBanner, {
      props: {
        status: {
          persisting: false,
          cause: 'failed to open access log database: disk I/O error',
        },
      },
    });
    const banner = screen.getByRole('alert');
    expect(banner).toHaveTextContent(
      `${MESSAGE}: failed to open access log database: disk I/O error`,
    );
  });

  it('still shows when the cause is not known', () => {
    render(LogStoreBanner, { props: { status: { persisting: false, cause: null } } });
    expect(screen.getByRole('alert')).toHaveTextContent(`${MESSAGE}: cause unknown`);
  });

  it('is absent while the node is persisting', () => {
    render(LogStoreBanner, { props: { status: { persisting: true, cause: null } } });
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('is absent before the first status read', () => {
    render(LogStoreBanner, { props: { status: null } });
    expect(screen.queryByRole('alert')).toBeNull();
  });
});
