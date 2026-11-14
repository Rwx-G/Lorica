import { describe, it, expect } from 'vitest';
import {
  parseNginxConfig,
  convertToLoricaRoutes,
  mergeRelatedRoutes,
  type LoricaRouteImport,
  type PathRuleImport,
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
    path_rules: [],
    return_status: null,
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

  it('handles the real app.example.com 3-server-block case', () => {
    const config = `
server {
    listen 80;
    server_name app.example.com www.app.example.com;
    return 301 https://app.example.com$request_uri;
}
server {
    listen 443 ssl;
    server_name www.app.example.com;
    return 301 https://app.example.com$request_uri;
}
server {
    listen 443 ssl;
    server_name app.example.com;
    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}
`;
    const parsed = parseNginxConfig(config);
    const routes = convertToLoricaRoutes(parsed);

    expect(routes).toHaveLength(1);
    expect(routes[0].hostname).toBe('app.example.com');
    expect(routes[0].force_https).toBe(true);
    expect(routes[0].backend_addresses).toEqual(['127.0.0.1:3000']);
    expect(routes[0].hostname_aliases).toContain('www.app.example.com');
    expect(routes[0].redirect_hostname).toBe('app.example.com');
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

describe('convertToLoricaRoutes - path rules', () => {
  it('multi-location server produces 1 route with path rules', () => {
    const config = `
server {
    listen 443 ssl;
    server_name app.example.com;
    location / {
        proxy_pass http://127.0.0.1:3000;
    }
    location /api {
        proxy_pass http://127.0.0.1:4000;
    }
    location /static {
        proxy_cache my_cache;
        proxy_cache_valid 200 10m;
        proxy_pass http://127.0.0.1:3000;
    }
}
`;
    const parsed = parseNginxConfig(config);
    const routes = convertToLoricaRoutes(parsed);

    expect(routes).toHaveLength(1);
    expect(routes[0].hostname).toBe('app.example.com');
    expect(routes[0].backend_addresses).toEqual(['127.0.0.1:3000']);
    expect(routes[0].path_rules).toHaveLength(2);

    // /api path rule should have different backend
    const apiRule = routes[0].path_rules.find(r => r.path === '/api');
    expect(apiRule).toBeDefined();
    expect(apiRule!.backend_addresses).toEqual(['127.0.0.1:4000']);
    expect(apiRule!.match_type).toBe('prefix');

    // /static path rule should have cache
    const staticRule = routes[0].path_rules.find(r => r.path === '/static');
    expect(staticRule).toBeDefined();
    expect(staticRule!.cache_enabled).toBe(true);
    expect(staticRule!.cache_ttl_s).toBe(600);
  });

  it('return 403 in location creates return_status path rule', () => {
    const config = `
server {
    listen 80;
    server_name example.com;
    location / {
        proxy_pass http://127.0.0.1:8080;
    }
    location /admin {
        return 403;
    }
}
`;
    const parsed = parseNginxConfig(config);
    const routes = convertToLoricaRoutes(parsed);

    expect(routes).toHaveLength(1);
    expect(routes[0].path_rules).toHaveLength(1);
    expect(routes[0].path_rules[0].path).toBe('/admin');
    expect(routes[0].path_rules[0].return_status).toBe(403);
  });

  it('different proxy_pass creates backend override path rule', () => {
    const config = `
server {
    listen 80;
    server_name example.com;
    location / {
        proxy_pass http://127.0.0.1:8080;
    }
    location /api {
        proxy_pass http://127.0.0.1:9090;
    }
}
`;
    const parsed = parseNginxConfig(config);
    const routes = convertToLoricaRoutes(parsed);

    expect(routes).toHaveLength(1);
    expect(routes[0].backend_addresses).toEqual(['127.0.0.1:8080']);
    expect(routes[0].path_rules).toHaveLength(1);
    expect(routes[0].path_rules[0].path).toBe('/api');
    expect(routes[0].path_rules[0].backend_addresses).toEqual(['127.0.0.1:9090']);
  });

  it('warns on if blocks', () => {
    const config = `
server {
    listen 80;
    server_name example.com;
    if ($http_user_agent ~* "bot") {
        return 403;
    }
    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}
`;
    const parsed = parseNginxConfig(config);
    const ifWarnings = parsed.diagnostics.filter(
      d => d.level === 'warning' && d.message.includes('if')
    );
    expect(ifWarnings.length).toBeGreaterThanOrEqual(1);
    expect(ifWarnings[0].message).toContain('skipped');
  });

  it('warns on non-standard listen ports', () => {
    const config = `
server {
    listen 8080;
    server_name example.com;
    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}
`;
    const parsed = parseNginxConfig(config);
    const portWarnings = parsed.diagnostics.filter(
      d => d.level === 'warning' && d.message.includes('Non-standard port')
    );
    expect(portWarnings).toHaveLength(1);
    expect(portWarnings[0].message).toContain('8080');
  });

  it('does not warn on standard ports 80 and 443', () => {
    const config = `
server {
    listen 80;
    listen 443 ssl;
    server_name example.com;
    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}
`;
    const parsed = parseNginxConfig(config);
    const portWarnings = parsed.diagnostics.filter(
      d => d.level === 'warning' && d.message.includes('Non-standard port')
    );
    expect(portWarnings).toHaveLength(0);
  });

  it('root location directives apply to the route itself', () => {
    const config = `
server {
    listen 80;
    server_name example.com;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_read_timeout 60s;
    }
}
`;
    const parsed = parseNginxConfig(config);
    const routes = convertToLoricaRoutes(parsed);

    expect(routes).toHaveLength(1);
    expect(routes[0].backend_addresses).toEqual(['127.0.0.1:8080']);
    expect(routes[0].read_timeout_s).toBe(60);
    expect(routes[0].path_rules).toHaveLength(0);
  });

  it('server with no locations still works', () => {
    const config = `
server {
    listen 80;
    server_name example.com;
    return 301 https://example.com$request_uri;
}
`;
    const parsed = parseNginxConfig(config);
    const routes = convertToLoricaRoutes(parsed);

    expect(routes).toHaveLength(1);
    expect(routes[0].force_https).toBe(true);
  });

  it('handles bare return status on route level', () => {
    const config = `
server {
    listen 80;
    server_name example.com;
    return 404;
}
`;
    const parsed = parseNginxConfig(config);
    const routes = convertToLoricaRoutes(parsed);

    expect(routes).toHaveLength(1);
    expect(routes[0].return_status).toBe(404);
  });
});

const HTTP_SITES = `
upstream app {
    server 10.0.0.20:3000;
    server 10.0.0.21:3000;
}
server {
    listen 80;
    server_name app.example.com;
    return 301 https://app.example.com$request_uri;
}
server {
    listen 443 ssl;
    server_name app.example.com;
    location / {
        proxy_pass http://app;
    }
    location /api {
        proxy_pass http://127.0.0.1:4000;
    }
}
server {
    listen 80;
    server_name static.example.com;
    proxy_pass http://127.0.0.1:8081;
}
`;

const MIXED_HTTP_STREAM = `
events {
    worker_connections 1024;
}
http {
${HTTP_SITES}
}
stream {
    upstream tls {
        server 10.0.0.40:443;
    }
    upstream db {
        server 10.0.0.10:5432;
    }
    server {
        listen 443;
        ssl_preread on;
        proxy_pass tls;
    }
    server {
        listen 5432;
        proxy_pass db;
    }
}
`;

describe('stream {} blocks', () => {
  const TLS_PASSTHROUGH = `
stream {
    upstream tls {
        server 10.0.0.40:443;
    }
    server {
        listen 443;
        ssl_preread on;
        proxy_pass tls;
    }
}
`;

  const DATABASE_STREAM = `
stream {
    upstream db {
        server 10.0.0.10:5432;
    }
    server {
        listen 5432;
        proxy_pass db;
    }
}
`;

  it('convertToLoricaRoutes (conversion layer): an ssl_preread passthrough yields no route', () => {
    const routes = convertToLoricaRoutes(parseNginxConfig(TLS_PASSTHROUGH));
    expect(routes).toHaveLength(0);
  });

  it('parseNginxConfig (parser layer): stream server and upstream stay out of the http results', () => {
    const parsed = parseNginxConfig(DATABASE_STREAM);
    expect(parsed.servers).toHaveLength(0);
    expect(parsed.upstreams).toHaveLength(0);
  });

  it('parseNginxConfig (parser layer): http {} and stream {} wrappers close without a brace error', () => {
    const httpWrapped = `
http {
    server {
        listen 80;
        server_name example.com;
        location / {
            proxy_pass http://127.0.0.1:8080;
        }
    }
}
`;
    for (const config of [httpWrapped, DATABASE_STREAM]) {
      const braceErrors = parseNginxConfig(config).diagnostics.filter(
        d => d.level === 'error' && d.message.includes('closing brace')
      );
      expect(braceErrors).toHaveLength(0);
    }
  });

  it('parseNginxConfig (parser layer): stream server and upstream land in the stream results', () => {
    const parsed = parseNginxConfig(DATABASE_STREAM);

    expect(parsed.streamUpstreams).toEqual([
      { name: 'db', servers: ['10.0.0.10:5432'], line: 3 },
    ]);
    expect(parsed.streamServers).toHaveLength(1);
    expect(parsed.streamServers[0].line).toBe(6);
    expect(parsed.streamServers[0].listen).toEqual(['5432']);
    expect(parsed.streamServers[0].proxyPass).toBe('db');
  });

  it('parseNginxConfig (parser layer): a stream server warns it was not imported, without the port hint', () => {
    const parsed = parseNginxConfig(DATABASE_STREAM);

    const warnings = parsed.diagnostics.filter(d => d.level === 'warning');
    expect(warnings).toHaveLength(1);
    expect(warnings[0].line).toBe(6);
    expect(warnings[0].message).toContain('not imported');
    expect(warnings[0].message).toContain('5432');
    expect(parsed.diagnostics.some(d => d.message.includes('Non-standard port'))).toBe(false);
  });

  it('parseNginxConfig (parser layer): an unknown block inside a location does not close the location', () => {
    const config = `
server {
    listen 80;
    server_name example.com;
    location / {
        proxy_pass http://127.0.0.1:8080;
    }
    location /api {
        limit_except GET {
            deny all;
        }
        proxy_pass http://127.0.0.1:9090;
    }
}
`;
    const parsed = parseNginxConfig(config);
    expect(parsed.diagnostics.filter(d => d.level === 'error')).toHaveLength(0);
    expect(parsed.servers).toHaveLength(1);
    const api = parsed.servers[0].locations.find(l => l.path === '/api');
    expect(api?.proxyPass).toBe('http://127.0.0.1:9090');

    const routes = convertToLoricaRoutes(parsed);
    expect(routes).toHaveLength(1);
    expect(routes[0].backend_addresses).toEqual(['127.0.0.1:8080']);
    expect(routes[0].path_rules).toHaveLength(1);
    expect(routes[0].path_rules[0].path).toBe('/api');
    expect(routes[0].path_rules[0].backend_addresses).toEqual(['127.0.0.1:9090']);
  });

  it('IV1: a mixed http {} + stream {} config imports the same HTTP routes and no stream route', () => {
    const routesBefore = convertToLoricaRoutes(parseNginxConfig(HTTP_SITES));
    const parsed = parseNginxConfig(MIXED_HTTP_STREAM);
    const routes = convertToLoricaRoutes(parsed);

    expect(routesBefore.map(r => r.hostname).sort()).toEqual(['app.example.com', 'static.example.com']);
    expect(routes).toEqual(routesBefore);

    expect(parsed.streamServers).toHaveLength(2);
    const notImported = parsed.diagnostics.filter(
      d => d.level === 'warning' && d.message.includes('not imported')
    );
    expect(notImported.map(d => d.line)).toEqual(parsed.streamServers.map(s => s.line));
    expect(parsed.diagnostics.filter(d => d.level === 'error')).toHaveLength(0);
  });
});

describe('mail {} blocks', () => {
  const MAIL = `
mail {
    server_name mail.example.com;
    auth_http 127.0.0.1:9000/auth;
    server {
        listen 443 ssl;
        protocol imap;
        proxy on;
    }
}
`;

  it('parseNginxConfig (parser layer): a mail server is skipped with one warning and no HTTP server', () => {
    const parsed = parseNginxConfig(MAIL);

    expect(parsed.servers).toHaveLength(0);
    expect(parsed.streamServers).toHaveLength(0);
    expect(parsed.diagnostics).toHaveLength(1);
    expect(parsed.diagnostics[0].level).toBe('warning');
    expect(parsed.diagnostics[0].line).toBe(5);
    expect(parsed.diagnostics[0].message).toContain('not imported');
    expect(parsed.diagnostics[0].message).toContain('mail');
  });

  it('convertToLoricaRoutes (conversion layer): a mail server on 443 with ssl yields no route', () => {
    expect(convertToLoricaRoutes(parseNginxConfig(MAIL))).toHaveLength(0);
  });

  it('IV1 with mail: a mixed http {} + stream {} + mail {} config imports the same HTTP routes', () => {
    const routesBefore = convertToLoricaRoutes(parseNginxConfig(HTTP_SITES));
    const parsed = parseNginxConfig(MIXED_HTTP_STREAM + MAIL);

    expect(convertToLoricaRoutes(parsed)).toEqual(routesBefore);
    expect(parsed.streamServers).toHaveLength(2);
    expect(parsed.diagnostics.filter(d => d.level === 'warning' && d.message.includes('not imported'))).toHaveLength(3);
    expect(parsed.diagnostics.filter(d => d.level === 'error')).toHaveLength(0);
  });
});
