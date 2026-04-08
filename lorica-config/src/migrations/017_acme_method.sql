-- Migration 017: Add ACME method and DNS config columns to certificates.
-- acme_method: "http01", "dns01-ovh", "dns01-cloudflare", "dns01-route53", "dns01-manual"
-- acme_dns_config: encrypted JSON with DNS provider credentials for auto-renewal

ALTER TABLE certificates ADD COLUMN acme_method TEXT DEFAULT NULL;
ALTER TABLE certificates ADD COLUMN acme_dns_config TEXT DEFAULT NULL;
