import { describe, it, expect } from 'vitest';
import {
  parseNginxConfig,
  convertToLoricaRoutes,
  mergeRelatedRoutes,
  type LoricaRouteImport,
} from './nginx-parser';

/** Helper: create a minimal route for merge testing. */
function makeRoute(overrides: Partial<LoricaRouteImport> = {}): LoricaRouteImport {
  return {
    hostname: '',
    path_prefix: '/',
    hostname_aliases: [],
    force_https: false,
    backend_addresses: [],
    certificate_needed: false,
    proxy_headers: {},
    response_headers: {},
    proxy_headers_remove: [],
    response_headers_remove: [],
    connect_timeout_s: 5,
    read_timeout_s: 30,
    send_timeout_s: 30,
    max_request_body_bytes: null,
    security_headers: 'none',
    strip_path_prefix: null,
    add_path_prefix: null,
    path_rewrite_pattern: null,
    path_rewrite_replacement: null,
    redirect_to: null,
    redirect_hostname: null,
    rate_limit_rps: null,
    rate_limit_burst: null,
    cache_enabled: false,
    cache_ttl_s: 0,
    importedFields: new Set<string>(),
    ...overrides,
  };
}

describe('mergeRelatedRoutes', () => {
  it('merges HTTP redirect-only route into HTTPS route with backends', () => {
    const httpRedirect = makeRoute({
      hostname: 'example.com',
      hostname_aliases: ['www.example.com'],
      force_https: true,
      backend_addresses: [],
    });
    const httpsRoute = makeRoute({
      hostname: 'example.com',
      backend_addresses: ['127.0.0.1:8080'],
      certificate_needed: true,
    });

    const result = mergeRelatedRoutes([httpRedirect, httpsRoute]);
    expect(result).toHaveLength(1);
    expect(result[0].hostname).toBe('example.com');
    expect(result[0].force_https).toBe(true);
    expect(result[0].backend_addresses).toEqual(['127.0.0.1:8080']);
    expect(result[0].hostname_aliases).toContain('www.example.com');
  });

  it('merges www redirect route into bare domain route', () => {
    const wwwRedirect = makeRoute({
      hostname: 'www.example.com',
      redirect_to: 'https://example.com',
    });
    const bareRoute = makeRoute({
      hostname: 'example.com',
      backend_addresses: ['127.0.0.1:8080'],
    });

    const result = mergeRelatedRoutes([wwwRedirect, bareRoute]);
    expect(result).toHaveLength(1);
    expect(result[0].hostname).toBe('example.com');
    expect(result[0].hostname_aliases).toContain('www.example.com');
    expect(result[0].redirect_hostname).toBe('example.com');
    expect(result[0].backend_addresses).toEqual(['127.0.0.1:8080']);
  });

  it('merges www force_https route (no redirect_to) into bare domain route', () => {
    const wwwRedirect = makeRoute({
      hostname: 'www.example.com',
      force_https: true,
      backend_addresses: [],
    });
    const bareRoute = makeRoute({
      hostname: 'example.com',
      backend_addresses: ['127.0.0.1:8080'],
    });

    const result = mergeRelatedRoutes([wwwRedirect, bareRoute]);
    expect(result).toHaveLength(1);
    expect(result[0].hostname).toBe('example.com');
    expect(result[0].hostname_aliases).toContain('www.example.com');
    expect(result[0].redirect_hostname).toBe('example.com');
  });

  it('does not merge routes with different path prefixes', () => {
    const routeA = makeRoute({
      hostname: 'example.com',
      path_prefix: '/api',
      force_https: true,
      backend_addresses: [],
    });
    const routeB = makeRoute({
      hostname: 'example.com',
      path_prefix: '/',
      backend_addresses: ['127.0.0.1:8080'],
    });

    const result = mergeRelatedRoutes([routeA, routeB]);
    expect(result).toHaveLength(2);
  });

  it('does not merge unrelated routes', () => {
    const routeA = makeRoute({
      hostname: 'a.com',
      backend_addresses: ['127.0.0.1:8080'],
    });
    const routeB = makeRoute({
      hostname: 'b.com',
      backend_addresses: ['127.0.0.1:9090'],
    });

    const result = mergeRelatedRoutes([routeA, routeB]);
    expect(result).toHaveLength(2);
  });

  it('handles the real stackoverkill.io 3-server-block case', () => {
    const config = `
server {
    listen 80;
    server_name stackoverkill.io www.stackoverkill.io;
    return 301 https://stackoverkill.io$request_uri;
}
server {
    listen 443 ssl;
    server_name www.stackoverkill.io;
    return 301 https://stackoverkill.io$request_uri;
}
server {
    listen 443 ssl;
    server_name stackoverkill.io;
    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}
`;
    const parsed = parseNginxConfig(config);
    const routes = convertToLoricaRoutes(parsed);

    expect(routes).toHaveLength(1);
    expect(routes[0].hostname).toBe('stackoverkill.io');
    expect(routes[0].force_https).toBe(true);
    expect(routes[0].backend_addresses).toEqual(['127.0.0.1:3000']);
    expect(routes[0].hostname_aliases).toContain('www.stackoverkill.io');
    expect(routes[0].redirect_hostname).toBe('stackoverkill.io');
  });

  it('preserves single route without modification', () => {
    const route = makeRoute({
      hostname: 'solo.com',
      backend_addresses: ['10.0.0.1:80'],
    });

    const result = mergeRelatedRoutes([route]);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe(route);
  });
});
