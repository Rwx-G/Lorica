// Shared constant maps and icons for the Nginx import wizard.

// Field labels for the preview cards.
export const FIELD_LABELS: Record<string, string> = {
  hostname: 'Hostname',
  path_prefix: 'Path prefix',
  hostname_aliases: 'Hostname aliases',
  force_https: 'Force HTTPS',
  redirect_to: 'Redirect to',
  redirect_hostname: 'Redirect hostname',
  backend_addresses: 'Backend addresses',
  certificate_needed: 'Certificate needed',
  proxy_headers: 'Proxy headers',
  response_headers: 'Response headers',
  proxy_headers_remove: 'Remove proxy headers',
  response_headers_remove: 'Remove response headers',
  connect_timeout_s: 'Connect timeout (s)',
  read_timeout_s: 'Read timeout (s)',
  send_timeout_s: 'Send timeout (s)',
  max_request_body_bytes: 'Max request body (bytes)',
  security_headers: 'Security headers',
  strip_path_prefix: 'Strip path prefix',
  add_path_prefix: 'Add path prefix',
  path_rewrite_pattern: 'Regex rewrite pattern',
  path_rewrite_replacement: 'Regex rewrite replacement',
  rate_limit_rps: 'Rate limit (RPS)',
  rate_limit_burst: 'Rate limit burst',
  cache_enabled: 'Cache enabled',
  cache_ttl_s: 'Cache TTL (s)',
  path_rules: 'Path rules',
  return_status: 'Return status',
};

// Map from Nginx directive names to display strings for the preview.
export const NGINX_DIRECTIVE_MAP: Record<string, string> = {
  hostname: 'server_name',
  path_prefix: 'location',
  hostname_aliases: 'server_name (aliases)',
  force_https: 'return 301 https://',
  redirect_to: 'return 301 https://other',
  redirect_hostname: 'return 301 (www redirect)',
  backend_addresses: 'proxy_pass / upstream',
  certificate_needed: 'ssl_certificate',
  proxy_headers: 'proxy_set_header',
  response_headers: 'add_header',
  proxy_headers_remove: 'proxy_hide_header',
  connect_timeout_s: 'proxy_connect_timeout',
  read_timeout_s: 'proxy_read_timeout',
  send_timeout_s: 'proxy_send_timeout',
  max_request_body_bytes: 'client_max_body_size',
  security_headers: 'add_header (security)',
  strip_path_prefix: 'rewrite (prefix strip)',
  path_rewrite_pattern: 'rewrite (regex)',
  path_rewrite_replacement: 'rewrite (regex)',
  rate_limit_rps: 'limit_req rate=',
  rate_limit_burst: 'limit_req burst=',
  cache_enabled: 'proxy_cache',
  cache_ttl_s: 'proxy_cache_valid',
  path_rules: 'location (sub-paths)',
  return_status: 'return (status)',
};

// Nginx directive -> Lorica parameter mapping for annotations.
export const LORICA_ANNOTATION: Record<string, string> = {
  server_name: 'hostname',
  proxy_pass: 'backend',
  ssl_certificate: 'certificate',
  ssl_certificate_key: 'certificate (key)',
  proxy_set_header: 'proxy_headers',
  add_header: 'response_headers',
  proxy_read_timeout: 'read_timeout_s',
  proxy_send_timeout: 'send_timeout_s',
  proxy_connect_timeout: 'connect_timeout_s',
  client_max_body_size: 'max_body_mb',
  proxy_cache_valid: 'cache_ttl_s',
  limit_req: 'rate_limit_rps',
  rewrite: 'path_rewrite',
  return: 'force_https / redirect_to',
  location: 'path_prefix',
};

// Builtin security header presets for comparison.
export const BUILTIN_PRESETS: Record<string, Record<string, string>> = {
  strict: {
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'self'",
    'Permissions-Policy': 'geolocation=(), camera=(), microphone=()',
    'X-XSS-Protection': '1; mode=block',
  },
  moderate: {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  },
};

export const WIZARD_STEP_LABELS = ['Paste', 'Analysis', 'Preview', 'Apply'];

export const CLOSE_ICON =
  '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
export const CHECK_ICON =
  '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
export const X_ICON =
  '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
