-- Migration 017: Add ACME method column to certificates.
-- acme_method: "http01", "dns01-ovh", "dns01-cloudflare", "dns01-route53", "dns01-manual"

ALTER TABLE certificates ADD COLUMN acme_method TEXT DEFAULT NULL;
