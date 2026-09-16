import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach } from 'vitest';

import { api, type RouteResponse } from '../../lib/api';
import CaptureRuleForm from './CaptureRuleForm.svelte';

function route(id: string, hostname: string): RouteResponse {
  // Only the fields the form reads; the rest is the API's business.
  return { id, hostname, path_prefix: '/' } as RouteResponse;
}

function renderForm(routes: RouteResponse[]) {
  const onsaved = vi.fn();
  const oncancel = vi.fn();
  render(CaptureRuleForm, { props: { routes, editing: null, onsaved, oncancel } });
  return { onsaved, oncancel };
}

function checkbox(label: string): HTMLInputElement {
  return screen.getByLabelText(label) as HTMLInputElement;
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('CaptureRuleForm refusals', () => {
  it('refuses to submit without a route', async () => {
    const create = vi.spyOn(api, 'createCaptureRule');
    renderForm([]);
    await fireEvent.input(screen.getByLabelText(/^Name/), { target: { value: 'checkout 5xx' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Arm rule' }));
    expect(screen.getByRole('alert').textContent).toMatch(/route/i);
    expect(create).not.toHaveBeenCalled();
  });

  it('refuses to submit without an emit condition', async () => {
    const create = vi.spyOn(api, 'createCaptureRule');
    renderForm([route('r1', 'shop.example.com')]);
    await fireEvent.input(screen.getByLabelText(/^Name/), { target: { value: 'everything' } });
    // 5xx is on by default; turning it off leaves no condition.
    await fireEvent.click(checkbox('Status 5xx'));
    await fireEvent.click(screen.getByRole('button', { name: 'Arm rule' }));
    expect(screen.getByRole('alert').textContent).toMatch(/acknowledge/i);
    expect(create).not.toHaveBeenCalled();
  });

  it('accepts a rule with no condition once "always" is acknowledged', async () => {
    const create = vi.spyOn(api, 'createCaptureRule').mockResolvedValue({
      data: { id: 'cap-1' } as never,
    });
    const { onsaved } = renderForm([route('r1', 'shop.example.com')]);
    await fireEvent.input(screen.getByLabelText(/^Name/), { target: { value: 'everything' } });
    await fireEvent.click(checkbox('Status 5xx'));
    const always = checkbox('Record every request on this route, unconditionally');
    expect(always.disabled).toBe(false);
    await fireEvent.click(always);
    await fireEvent.click(screen.getByRole('button', { name: 'Arm rule' }));
    await waitFor(() => expect(onsaved).toHaveBeenCalled());
    expect(create).toHaveBeenCalledTimes(1);
    const body = create.mock.calls[0][0];
    expect(body.route_id).toBe('r1');
    expect(body.emit).toEqual({ always: true, status: [], min_latency_ms: null, upstream_error: false });
  });

  it('keeps "always" out of reach while a condition is set', () => {
    renderForm([route('r1', 'shop.example.com')]);
    // 5xx is on, so the unbounded acknowledgement cannot be ticked by
    // accident; the two are exclusive server-side too.
    expect(checkbox('Record every request on this route, unconditionally').disabled).toBe(true);
  });

  it('shows the expiry the TTL produces as the operator types', async () => {
    renderForm([route('r1', 'shop.example.com')]);
    const before = new Date();
    const ttl = screen.getByLabelText(/^TTL/);
    await fireEvent.input(ttl, { target: { value: '7200' } });
    const preview = screen.getByTestId('expires-preview').textContent ?? '';
    expect(preview).toMatch(/Expires at/);
    // The preview is a locale string; the anchor is the open time, so
    // the shown instant is within a few seconds of before + 2 h.
    const shown = new Date(preview.replace(/^\s*Expires at\s*/, '').trim());
    if (!Number.isNaN(shown.getTime())) {
      const drift = Math.abs(shown.getTime() - (before.getTime() + 7200 * 1000));
      expect(drift).toBeLessThan(60_000);
    }
  });
});
