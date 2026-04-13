// Import pipeline helpers for the Nginx import wizard.
//
// These helpers encapsulate the synchronous route-request build and the
// async import orchestration (backends, security presets, certificates,
// routes). Kept in a plain TypeScript module so the Svelte component
// stays focused on state and presentation.

import { api, type CreateBackendRequest } from '../../lib/api';
import {
  formStateToCreateRequest,
  ROUTE_DEFAULTS,
  type RouteFormState,
} from '../../lib/route-form';
import type { LoricaRouteImport, PathRuleImport } from '../../lib/nginx-parser';
import { BUILTIN_PRESETS } from './maps';
import type { ApplyResult, BackendCheck, CertEntry } from './types';

/**
 * Build a CreateRouteRequest from a LoricaRouteImport using a
 * (backend_address -> backend_id) map to resolve references.
 */
export function buildCreateRequest(
  route: LoricaRouteImport,
  backendIdMap: Map<string, string>,
): ReturnType<typeof formStateToCreateRequest> {
  const backendIds: string[] = [];
  for (const addr of route.backend_addresses) {
    const id = backendIdMap.get(addr);
    if (id) backendIds.push(id);
  }

  const form: RouteFormState = {
    ...ROUTE_DEFAULTS,
    hostname: route.hostname,
    path_prefix: route.path_prefix || '/',
    backend_ids: backendIds,
    force_https: route.force_https,
    redirect_to: route.redirect_to ?? '',
    redirect_hostname: route.redirect_hostname ?? '',
    connect_timeout_s: route.connect_timeout_s,
    read_timeout_s: route.read_timeout_s,
    send_timeout_s: route.send_timeout_s,
    security_headers: route.security_headers,
    cache_enabled: route.cache_enabled,
    cache_ttl_s: route.cache_ttl_s,
    hostname_aliases: route.hostname_aliases.join(', '),
    strip_path_prefix: route.strip_path_prefix ?? '',
    add_path_prefix: route.add_path_prefix ?? '',
    path_rewrite_pattern: route.path_rewrite_pattern ?? '',
    path_rewrite_replacement: route.path_rewrite_replacement ?? '',
    max_body_mb:
      route.max_request_body_bytes != null
        ? String(route.max_request_body_bytes / (1024 * 1024))
        : '',
    rate_limit_rps: route.rate_limit_rps != null ? String(route.rate_limit_rps) : '',
    rate_limit_burst:
      route.rate_limit_burst != null ? String(route.rate_limit_burst) : '',
    proxy_headers: Object.entries(route.proxy_headers)
      .map(([k, v]) => `${k}=${v}`)
      .join('\n'),
    proxy_headers_remove: route.proxy_headers_remove.join(', '),
    response_headers: Object.entries(route.response_headers)
      .map(([k, v]) => `${k}=${v}`)
      .join('\n'),
    response_headers_remove: route.response_headers_remove.join(', '),
    path_rules: (route.path_rules ?? []).map((pr: PathRuleImport) => ({
      path: pr.path,
      match_type: pr.match_type ?? 'prefix',
      backend_ids: (pr.backend_addresses ?? [])
        .map((a) => backendIdMap.get(a))
        .filter((id): id is string => !!id),
      cache_enabled: pr.cache_enabled ?? null,
      cache_ttl_s: pr.cache_ttl_s ?? null,
      response_headers: pr.response_headers
        ? Object.entries(pr.response_headers)
            .map(([k, v]) => `${k}=${v}`)
            .join('\n')
        : '',
      response_headers_remove: '',
      rate_limit_rps: pr.rate_limit_rps != null ? String(pr.rate_limit_rps) : '',
      rate_limit_burst: pr.rate_limit_burst != null ? String(pr.rate_limit_burst) : '',
      redirect_to: pr.redirect_to ?? '',
      return_status: pr.return_status != null ? String(pr.return_status) : '',
    })),
    return_status: route.return_status != null ? String(route.return_status) : '',
  };

  return formStateToCreateRequest(form);
}

/** Case-insensitive equality of two header maps. */
function headersMatch(
  a: Record<string, string>,
  b: Record<string, string>,
): boolean {
  const normA = Object.fromEntries(
    Object.entries(a).map(([k, v]) => [k.toLowerCase(), v]),
  );
  const normB = Object.fromEntries(
    Object.entries(b).map(([k, v]) => [k.toLowerCase(), v]),
  );
  const keysA = Object.keys(normA).sort();
  const keysB = Object.keys(normB).sort();
  if (keysA.length !== keysB.length) return false;
  return keysA.every((k, i) => k === keysB[i] && normA[k] === normB[k]);
}

/**
 * Resolve `security_headers === 'auto'` references on imported routes by
 * matching their _securityHeaders against known builtin/custom presets,
 * creating new custom presets for unmatched configurations.
 *
 * Mutates `importRoutes[i].security_headers` in place and appends to
 * `applyResults`.
 */
export async function resolveSecurityPresets(
  importRoutes: LoricaRouteImport[],
  appendResult: (r: ApplyResult) => void,
): Promise<void> {
  const routesWithAuto = importRoutes.filter(
    (r) => r.security_headers === 'auto' && r._securityHeaders,
  );
  if (routesWithAuto.length === 0) return;

  const settingsRes = await api.getSettings();
  const customPresets: Record<string, Record<string, string>> = {};
  if (settingsRes.data?.custom_security_presets) {
    for (const p of settingsRes.data.custom_security_presets) {
      customPresets[p.name] = p.headers;
    }
  }

  const allPresets = { ...BUILTIN_PRESETS, ...customPresets };
  const newPresets: { name: string; headers: Record<string, string> }[] = [];

  for (const route of routesWithAuto) {
    const imported = route._securityHeaders!;

    let matched: string | null = null;
    for (const [name, headers] of Object.entries(allPresets)) {
      if (headersMatch(imported, headers)) {
        matched = name;
        break;
      }
    }

    if (matched) {
      route.security_headers = matched;
    } else {
      const presetName = route.hostname || 'imported';
      if (!allPresets[presetName]) {
        newPresets.push({ name: presetName, headers: imported });
        allPresets[presetName] = imported;
      }
      route.security_headers = presetName;
    }
  }

  if (newPresets.length > 0) {
    const existingList = settingsRes.data?.custom_security_presets ?? [];
    const merged = [...existingList, ...newPresets];
    const res = await api.updateSettings({ custom_security_presets: merged });
    if (res.error) {
      appendResult({
        type: 'backend',
        label: 'Security presets',
        success: false,
        error: res.error.message,
      });
    } else {
      for (const p of newPresets) {
        appendResult({
          type: 'backend',
          label: `Security preset "${p.name}"`,
          success: true,
        });
      }
    }
  }
}

/**
 * Full import orchestration:
 *   1. Sync tls_skip_verify on existing backends that need it.
 *   2. Create new backends flagged in backendChecks.
 *   3. Resolve security-header presets.
 *   4. Provision/import TLS certificates.
 *   5. Create routes, attaching certificate_id when available.
 *
 * Returns the ordered list of ApplyResult entries. Mutates
 * `importRoutes[i].security_headers` as a side-effect of preset resolution.
 */
export async function runImport(
  importRoutes: LoricaRouteImport[],
  backendChecks: BackendCheck[],
  certEntries: CertEntry[],
): Promise<ApplyResult[]> {
  const applyResults: ApplyResult[] = [];
  const appendResult = (r: ApplyResult) => {
    applyResults.push(r);
  };

  // Collect backend addresses that need tls_skip_verify
  const tlsSkipVerifyAddresses = new Set<string>();
  for (const route of importRoutes) {
    if (route._backendTlsSkipVerify) {
      for (const addr of route.backend_addresses) {
        tlsSkipVerifyAddresses.add(addr);
      }
    }
  }

  const backendIdMap = new Map<string, string>();

  // Update tls_skip_verify on existing backends where needed
  for (const check of backendChecks) {
    if (check.exists && check.existingId) {
      backendIdMap.set(check.address, check.existingId);
      if (tlsSkipVerifyAddresses.has(check.address)) {
        await api.updateBackend(check.existingId, { tls_skip_verify: true });
      }
    }
  }

  // Create new backends
  for (const check of backendChecks) {
    if (check.willCreate && !check.exists) {
      const body: CreateBackendRequest = {
        address: check.address,
        name: check.address,
        tls_skip_verify: tlsSkipVerifyAddresses.has(check.address) || undefined,
      };
      const res = await api.createBackend(body);
      if (res.error) {
        appendResult({
          type: 'backend',
          label: check.address,
          success: false,
          error: res.error.message,
        });
      } else if (res.data) {
        backendIdMap.set(check.address, res.data.id);
        appendResult({ type: 'backend', label: check.address, success: true });
      }
    }
  }

  // Resolve / create security presets
  await resolveSecurityPresets(importRoutes, appendResult);

  // Create TLS certificates
  const certIdMap = new Map<string, string>();
  for (const cert of certEntries) {
    if (cert.mode === 'skip') continue;

    if (cert.mode === 'acme') {
      const allDomains = [cert.hostname, ...cert.aliases].join(', ');
      const res = await api.provisionAcme({ domain: allDomains, staging: false });
      if (res.error) {
        appendResult({
          type: 'backend',
          label: `ACME certificate ${cert.hostname}`,
          success: false,
          error: res.error.message,
        });
      } else if (res.data) {
        const certsRes = await api.listCertificates();
        if (certsRes.data) {
          const newCert = certsRes.data.certificates.find(
            (c) => c.domain === cert.hostname,
          );
          if (newCert) {
            certIdMap.set(cert.hostname, newCert.id);
            for (const alias of cert.aliases) {
              certIdMap.set(alias, newCert.id);
            }
          }
        }
        appendResult({
          type: 'backend',
          label: `ACME certificate ${allDomains}`,
          success: true,
        });
      }
    } else if (cert.mode === 'import') {
      if (!cert.certContent.trim() || !cert.keyContent.trim()) continue;
      const res = await api.createCertificate({
        domain: cert.hostname,
        cert_pem: cert.certContent.trim(),
        key_pem: cert.keyContent.trim(),
      });
      if (res.error) {
        appendResult({
          type: 'backend',
          label: `Certificate ${cert.hostname}`,
          success: false,
          error: res.error.message,
        });
      } else if (res.data) {
        certIdMap.set(cert.hostname, res.data.id);
        for (const alias of cert.aliases) {
          certIdMap.set(alias, res.data.id);
        }
        appendResult({
          type: 'backend',
          label: `Certificate ${cert.hostname}`,
          success: true,
        });
      }
    }
  }

  // Create routes
  for (const route of importRoutes) {
    const req = buildCreateRequest(route, backendIdMap);
    const certId = certIdMap.get(route.hostname);
    if (certId) {
      req.certificate_id = certId;
    }
    const label = `${route.hostname}${route.path_prefix}`;
    const res = await api.createRoute(req);
    if (res.error) {
      appendResult({
        type: 'route',
        label,
        success: false,
        error: res.error.message,
      });
    } else if (res.data) {
      appendResult({ type: 'route', label, success: true, routeId: res.data.id });
    }
  }

  return applyResults;
}
