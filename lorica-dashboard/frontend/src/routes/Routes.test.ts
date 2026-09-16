import { render, screen, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { auth } from '../lib/auth';
import { api, type RouteResponse } from '../lib/api';
import { clusterStatus } from '../lib/cluster';
import Routes from './Routes.svelte';

function route(overrides: Partial<RouteResponse> = {}): RouteResponse {
  return {
    id: 'route-1',
    hostname: 'shop.example.com',
    path_prefix: '/',
    backends: [],
    certificate_id: null,
    load_balancing: 'round_robin',
    waf_enabled: false,
    waf_mode: 'detection',
    enabled: true,
    force_https: false,
    redirect_hostname: null,
    redirect_to: null,
    hostname_aliases: [],
    proxy_headers: {},
    response_headers: {},
    security_headers: 'none',
    connect_timeout_s: 5,
    read_timeout_s: 30,
    send_timeout_s: 30,
    strip_path_prefix: null,
    add_path_prefix: null,
    path_rewrite_pattern: null,
    path_rewrite_replacement: null,
    access_log_enabled: true,
    proxy_headers_remove: [],
    response_headers_remove: [],
    max_request_body_bytes: null,
    websocket_enabled: false,
    rate_limit_rps: null,
    rate_limit_burst: null,
    ip_allowlist: [],
    ip_denylist: [],
    cors_allowed_origins: [],
    cors_allowed_methods: [],
    cors_max_age_s: null,
    compression_enabled: false,
    retry_attempts: null,
    cache_enabled: false,
    cache_ttl_s: 0,
    cache_max_bytes: 0,
    max_connections: null,
    slowloris_threshold_ms: 0,
    auto_ban_threshold: null,
    auto_ban_duration_s: 0,
    path_rules: [],
    return_status: null,
    sticky_session: false,
    basic_auth_username: null,
    stale_while_revalidate_s: 0,
    stale_if_error_s: 0,
    retry_on_methods: [],
    maintenance_mode: false,
    error_page_html: null,
    cache_vary_headers: [],
    header_rules: [],
    traffic_splits: [],
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

const managedRoute = route({
  id: 'route-2',
  hostname: 'pr-42.review.example.com',
  managed_by: { kind: 'automation', environment: 'pr-42' },
});

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api, 'listRoutes').mockResolvedValue({ data: { routes: [route(), managedRoute] } });
  vi.spyOn(api, 'listBackends').mockResolvedValue({ data: { backends: [] } });
  vi.spyOn(api, 'listCertificates').mockResolvedValue({ data: { certificates: [] } });
  auth.set({ status: 'authenticated', username: 'someone', role: 'operator' });
});

afterEach(() => {
  clusterStatus.set(null);
  auth.set({ status: 'unauthenticated' });
});

describe('Routes page: rows the automation API owns (Story 10.4 AC #8)', () => {
  it('badges a managed route with its environment and not a plain one', async () => {
    render(Routes);
    await screen.findByText('pr-42.review.example.com');
    const badge = screen.getByTitle('Managed by the automation API for environment "pr-42"');
    expect(badge).toHaveTextContent('automation');
    expect(badge).toHaveTextContent('pr-42');
    expect(screen.getAllByText('automation')).toHaveLength(1);
  });

  it('disables Edit and the maintenance toggle on a managed route and leaves a plain one editable', async () => {
    render(Routes);
    const managedEdit = await screen.findByRole('button', { name: 'Edit pr-42.review.example.com/' });
    expect(managedEdit).toBeDisabled();
    expect(managedEdit).toHaveAttribute(
      'title',
      'Managed by the automation API for environment "pr-42". Update it through the pipeline: the next PUT would overwrite a manual change.',
    );
    expect(screen.getByRole('button', { name: 'Edit shop.example.com/' })).toBeEnabled();

    const toggles = screen.getAllByRole('button', { name: 'Enable maintenance' });
    expect(toggles).toHaveLength(2);
    expect(toggles[0]).toBeEnabled();
    expect(toggles[1]).toBeDisabled();
  });

  it('keeps Delete available on a managed route and names the environment in the confirmation', async () => {
    render(Routes);
    const del = await screen.findByRole('button', { name: 'Delete pr-42.review.example.com/' });
    expect(del).toBeEnabled();
    await fireEvent.click(del);
    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveTextContent('the whole environment "pr-42" is deleted with it');
  });

  it('confirms a plain route delete without mentioning an environment', async () => {
    render(Routes);
    await fireEvent.click(await screen.findByRole('button', { name: 'Delete shop.example.com/' }));
    expect(screen.getByRole('dialog')).not.toHaveTextContent('environment');
  });
});
