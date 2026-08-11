<script lang="ts">
  import { validateCidr } from '../../lib/validators';
  import { isSuperAdmin } from '../../lib/auth';

  function cidrListErr(text: string): string | null {
    const raw = text.trim();
    if (raw === '') return null;
    const entries = raw.split(/[,\n]/).map((s) => s.trim()).filter((s) => s.length > 0);
    for (let i = 0; i < entries.length; i++) {
      const e = validateCidr(entries[i]);
      if (e) return `line ${i + 1} (${entries[i]}): ${e}`;
    }
    return null;
  }

  interface NetworkFormShape {
    trusted_proxies: string;
    connection_deny_cidrs: string;
    connection_allow_cidrs: string;
    geoip_db_path: string;
    geoip_auto_update_enabled: boolean;
    asn_db_path: string;
    asn_auto_update_enabled: boolean;
    // Defense-in-depth data-plane bounds (Story 8.9).
    // connection_limits_per_ip is a free-form text field so an
    // empty input means "no cap" (mapped to null on save).
    audit_log_retention_days: number;
    connection_limits_per_ip: string;
    bot_stash_max_entries: number;
    bot_stash_per_prefix_max: number;
    mirror_max_concurrent_per_route: number;
    mirror_max_concurrent_global: number;
  }

  interface Props {
    settingsForm: NetworkFormShape;
    expanded: boolean;
    toggleSection: () => void;
    onSave: () => void | Promise<void>;
    settingsSaving: boolean;
    settingsMsg: string;
    settingsError: string;
  }

  let {
    settingsForm = $bindable(),
    expanded,
    toggleSection,
    onSave,
    settingsSaving,
    settingsMsg,
    settingsError,
  }: Props = $props();

  let trustedProxiesErr = $state<string | null>(null);
  let denyCidrsErr = $state<string | null>(null);
  let allowCidrsErr = $state<string | null>(null);
  function checkTrustedProxies() { trustedProxiesErr = cidrListErr(settingsForm.trusted_proxies); }
  function checkDenyCidrs() { denyCidrsErr = cidrListErr(settingsForm.connection_deny_cidrs); }
  function checkAllowCidrs() { allowCidrsErr = cidrListErr(settingsForm.connection_allow_cidrs); }

  // Defense-in-depth numeric bounds (Story 8.9). Empty is treated
  // as "unset"; the connection limit additionally accepts 0 as
  // "no cap".
  function numErr(raw: number | string, min: number, max: number): string | null {
    const str = String(raw).trim();
    if (str === '') return null;
    const n = Number(str);
    if (!Number.isInteger(n) || n < min || n > max) {
      return `value must be an integer in ${min}..${max}`;
    }
    return null;
  }
  let auditRetentionErr = $state<string | null>(null);
  let connLimitErr = $state<string | null>(null);
  let botStashMaxErr = $state<string | null>(null);
  let botStashPrefixErr = $state<string | null>(null);
  let mirrorRouteErr = $state<string | null>(null);
  let mirrorGlobalErr = $state<string | null>(null);
  function checkAuditRetention() { auditRetentionErr = numErr(settingsForm.audit_log_retention_days, 1, 3650); }
  function checkConnLimit() { connLimitErr = numErr(settingsForm.connection_limits_per_ip, 0, 1_000_000); }
  function checkBotStashMax() { botStashMaxErr = numErr(settingsForm.bot_stash_max_entries, 1, 10_000_000); }
  function checkBotStashPrefix() { botStashPrefixErr = numErr(settingsForm.bot_stash_per_prefix_max, 1, 1_000_000); }
  function checkMirrorRoute() { mirrorRouteErr = numErr(settingsForm.mirror_max_concurrent_per_route, 1, 1_000_000); }
  function checkMirrorGlobal() { mirrorGlobalErr = numErr(settingsForm.mirror_max_concurrent_global, 1, 1_000_000); }
</script>

<section class="settings-section">
  <button class="settings-collapsible-header" class:open={expanded} onclick={toggleSection}>
    <h2>Network</h2>
    <span class="settings-chevron" class:expanded></span>
  </button>
  {#if expanded}
    <div class="settings-section-body">
      <p class="section-hint">
        Network-level request filtering and IP intelligence databases.
        Trusted-proxy / allow / deny rules gate connections at accept time.
        GeoIP and ASN databases enrich the request with country and ASN
        metadata for per-route allow / deny rules and bot-protection bypass
        rules. All settings hot-reload on save.
      </p>

      <h3>Proxy trust &amp; connection filter</h3>

      <div class="settings-form-row">
        <label for="trusted-proxies">Trusted Proxies (CIDR)</label>
        <textarea
          id="trusted-proxies"
          rows="4"
          bind:value={settingsForm.trusted_proxies}
          placeholder="192.168.0.0/16&#10;10.0.0.0/8&#10;172.16.0.0/12"
          onblur={checkTrustedProxies} oninput={checkTrustedProxies}
        ></textarea>
        {#if trustedProxiesErr}<span class="field-error" role="alert">{trustedProxiesErr}</span>{/if}
        <span class="hint">
          One CIDR range or IP per line. X-Forwarded-For is only trusted from
          these addresses. Empty = trust no XFF (direct client IP always used).
        </span>
      </div>

      <div class="settings-form-row">
        <label for="conn-deny">Connection Deny CIDRs</label>
        <textarea
          id="conn-deny"
          rows="3"
          bind:value={settingsForm.connection_deny_cidrs}
          placeholder="198.51.100.0/24&#10;2001:db8::/32"
          onblur={checkDenyCidrs} oninput={checkDenyCidrs}
        ></textarea>
        {#if denyCidrsErr}<span class="field-error" role="alert">{denyCidrsErr}</span>{/if}
        <span class="hint">
          One IP or CIDR per line. Matching connections are dropped at TCP
          accept, before TLS handshake. Evaluated after the allow list; deny
          always wins.
        </span>
      </div>

      <div class="settings-form-row">
        <label for="conn-allow">Connection Allow CIDRs</label>
        <textarea
          id="conn-allow"
          rows="3"
          bind:value={settingsForm.connection_allow_cidrs}
          placeholder="10.0.0.0/8&#10;192.168.0.0/16"
          onblur={checkAllowCidrs} oninput={checkAllowCidrs}
        ></textarea>
        {#if allowCidrsErr}<span class="field-error" role="alert">{allowCidrsErr}</span>{/if}
        <span class="hint">
          One IP or CIDR per line. Leave empty for default-allow. When
          non-empty, switches the pre-filter to default-deny: only listed IPs
          are accepted.
        </span>
      </div>

      <h3>GeoIP (country database)</h3>

      <div class="settings-form-row">
        <label for="geoip-db-path">GeoIP database path</label>
        <input
          id="geoip-db-path"
          type="text"
          bind:value={settingsForm.geoip_db_path}
          placeholder="/var/lib/lorica/dbip-country-lite.mmdb"
          autocomplete="off"
        />
        <span class="hint">
          Absolute path to a <code>.mmdb</code> country database. Default
          source is DB-IP Lite Country (CC-BY 4.0, monthly refresh, no account).
          Hot-reloaded on save.
        </span>
      </div>

      <div class="settings-form-row">
        <label class="toggle-label" for="geoip-auto-update">
          <input
            id="geoip-auto-update"
            type="checkbox"
            bind:checked={settingsForm.geoip_auto_update_enabled}
          />
          Auto-update weekly
        </label>
        <span class="hint">
          Downloads the current month's DB-IP Lite weekly, validates via a
          sanity probe, and atomic-renames onto <code>geoip_db_path</code>.
          Opt in after reading the CC-BY 4.0 attribution note in
          <code>NOTICE</code>.
        </span>
      </div>

      <h3>ASN database</h3>

      <div class="settings-form-row">
        <label for="asn-db-path">ASN database path</label>
        <input
          id="asn-db-path"
          type="text"
          bind:value={settingsForm.asn_db_path}
          placeholder="/var/lib/lorica/dbip-asn-lite.mmdb"
          autocomplete="off"
        />
        <span class="hint">
          Absolute path to a <code>.mmdb</code> ASN database. DB-IP ASN Lite
          (CC-BY 4.0) is the free default source. Required for the
          <code>bypass.asns</code> category on the bot-protection filter; an
          unset path makes that bypass a silent no-op.
        </span>
      </div>

      <div class="settings-form-row">
        <label class="toggle-label" for="asn-auto-update">
          <input
            id="asn-auto-update"
            type="checkbox"
            bind:checked={settingsForm.asn_auto_update_enabled}
          />
          Auto-update weekly
        </label>
        <span class="hint">
          Downloads the current month's DB-IP ASN Lite weekly, validates via a
          sanity probe, and atomic-renames onto <code>asn_db_path</code>.
          Opt in after reading the CC-BY 4.0 attribution note in
          <code>NOTICE</code>.
        </span>
      </div>

      <h3>Defense in depth</h3>
      <p class="section-hint">
        Data-plane hardening bounds. Caps on connection fan-out,
        bot-challenge memory, request-mirroring concurrency, and
        audit-log retention. All hot-reload on save.
      </p>

      <div class="settings-form-row">
        <label for="audit-retention">Audit log retention (days)</label>
        <input
          id="audit-retention"
          type="number"
          min="1"
          max="3650"
          bind:value={settingsForm.audit_log_retention_days}
          onblur={checkAuditRetention} oninput={checkAuditRetention}
        />
        {#if auditRetentionErr}<span class="field-error" role="alert">{auditRetentionErr}</span>{/if}
        <span class="hint">Operator audit records older than this are purged. Default 90.</span>
      </div>

      <div class="settings-form-row">
        <label for="conn-limit-per-ip">Connection limit per IP</label>
        <input
          id="conn-limit-per-ip"
          type="text"
          inputmode="numeric"
          bind:value={settingsForm.connection_limits_per_ip}
          placeholder="(no cap)"
          autocomplete="off"
          onblur={checkConnLimit} oninput={checkConnLimit}
        />
        {#if connLimitErr}<span class="field-error" role="alert">{connLimitErr}</span>{/if}
        <span class="hint">
          Max simultaneous connections from a single client IP,
          dropped at accept time above the cap. Empty or 0 = no cap.
        </span>
      </div>

      <div class="settings-form-row">
        <label for="bot-stash-max">Bot challenge stash - max entries</label>
        <input
          id="bot-stash-max"
          type="number"
          min="1"
          max="10000000"
          bind:value={settingsForm.bot_stash_max_entries}
          onblur={checkBotStashMax} oninput={checkBotStashMax}
        />
        {#if botStashMaxErr}<span class="field-error" role="alert">{botStashMaxErr}</span>{/if}
        <span class="hint">Global cap on stored bot-protection challenge entries. Default 10000.</span>
      </div>

      <div class="settings-form-row">
        <label for="bot-stash-prefix">Bot challenge stash - per-prefix max</label>
        <input
          id="bot-stash-prefix"
          type="number"
          min="1"
          max="1000000"
          bind:value={settingsForm.bot_stash_per_prefix_max}
          onblur={checkBotStashPrefix} oninput={checkBotStashPrefix}
        />
        {#if botStashPrefixErr}<span class="field-error" role="alert">{botStashPrefixErr}</span>{/if}
        <span class="hint">Per source-prefix cap on bot-protection challenge entries. Default 100.</span>
      </div>

      <div class="settings-form-row">
        <label for="mirror-per-route">Mirror concurrency - per route</label>
        <input
          id="mirror-per-route"
          type="number"
          min="1"
          max="1000000"
          bind:value={settingsForm.mirror_max_concurrent_per_route}
          onblur={checkMirrorRoute} oninput={checkMirrorRoute}
        />
        {#if mirrorRouteErr}<span class="field-error" role="alert">{mirrorRouteErr}</span>{/if}
        <span class="hint">Cap on in-flight mirrored requests per route. Default 32.</span>
      </div>

      <div class="settings-form-row">
        <label for="mirror-global">Mirror concurrency - global</label>
        <input
          id="mirror-global"
          type="number"
          min="1"
          max="1000000"
          bind:value={settingsForm.mirror_max_concurrent_global}
          onblur={checkMirrorGlobal} oninput={checkMirrorGlobal}
        />
        {#if mirrorGlobalErr}<span class="field-error" role="alert">{mirrorGlobalErr}</span>{/if}
        <span class="hint">Global cap on in-flight mirrored requests. Default 4096.</span>
      </div>

      {#if settingsError}
        <div class="settings-form-error">{settingsError}</div>
      {/if}
      {#if $isSuperAdmin}
        <div class="settings-dialog-actions">
          <button class="btn btn-primary" onclick={onSave} disabled={settingsSaving}>
            {settingsSaving ? 'Saving...' : 'Save Network Settings'}
          </button>
        </div>
      {/if}
    </div>
  {/if}
</section>

<style>
  .section-hint {
    color: var(--color-text-muted, #666);
    font-size: 0.9em;
    margin: 0 0 1rem;
  }
  .hint {
    display: block;
    font-size: 0.75rem;
    color: var(--color-text-muted);
    margin-top: 0.25rem;
  }
  h3 {
    margin: var(--space-4) 0 var(--space-2);
    font-size: var(--text-md);
    color: var(--color-text-heading);
    border-top: 1px solid var(--color-border);
    padding-top: var(--space-4);
  }
  .toggle-label {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-size: var(--text-sm);
    color: var(--color-text-muted);
  }
  .field-error { display: block; color: var(--color-red); font-size: var(--text-xs); margin-top: 0.25rem; }
</style>
