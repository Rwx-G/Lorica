<script lang="ts">
  import type { RouteFormState } from '../../lib/route-form';
  import { ROUTE_DEFAULTS } from '../../lib/route-form';

  interface Props {
    form: RouteFormState;
    importedFields?: Set<string>;
  }

  let { form = $bindable(), importedFields }: Props = $props();

  function isModified(field: keyof RouteFormState): boolean {
    return ROUTE_DEFAULTS[field] !== form[field];
  }

  function isImported(field: string): boolean {
    return importedFields?.has(field) ?? false;
  }
</script>

<div class="tab-content">
  <div class="form-row">
    <div class="form-group" class:modified={isModified('max_connections')}>
      <label for="max-connections">Max connections</label>
      {#if isImported('max_connections')}<span class="imported-badge">imported</span>{/if}
      <input id="max-connections" type="number" min="1" bind:value={form.max_connections} placeholder="No limit" />
      <span class="hint">Nginx: limit_conn | HAProxy: maxconn per backend</span>
    </div>
    <div class="form-group" class:modified={isModified('slowloris_threshold_ms')}>
      <label for="slowloris-threshold">Slowloris threshold (ms)</label>
      {#if isImported('slowloris_threshold_ms')}<span class="imported-badge">imported</span>{/if}
      <input id="slowloris-threshold" type="number" min="100" bind:value={form.slowloris_threshold_ms} placeholder="5000" />
      <span class="hint">Nginx: client_header_timeout | HAProxy: timeout http-request</span>
    </div>
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={isModified('auto_ban_threshold')}>
      <label for="auto-ban-threshold">Auto-ban threshold <span class="hint">(violations before ban)</span></label>
      {#if isImported('auto_ban_threshold')}<span class="imported-badge">imported</span>{/if}
      <input id="auto-ban-threshold" type="number" min="1" bind:value={form.auto_ban_threshold} placeholder="Disabled" />
      <span class="hint">Fail2ban-like behavior built into the proxy</span>
    </div>
    <div class="form-group" class:modified={isModified('auto_ban_duration_s')}>
      <label for="auto-ban-duration">Auto-ban duration (s)</label>
      {#if isImported('auto_ban_duration_s')}<span class="imported-badge">imported</span>{/if}
      <input id="auto-ban-duration" type="number" min="1" bind:value={form.auto_ban_duration_s} placeholder="3600" />
    </div>
  </div>

  <div class="section-divider">
    <h4>Rate limit <span class="hint">(token bucket, cross-worker)</span></h4>
    <p class="section-hint">
      Cross-worker under <code>--workers N</code>: every worker's local bucket is
      synced with the supervisor every 100 ms. Leave capacity empty to disable.
      See <code>docs/architecture/worker-shared-state.md</code> § 6.
    </p>
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={isModified('rate_limit_capacity')}>
      <label for="rate-limit-capacity">Capacity <span class="hint">(burst tokens)</span></label>
      {#if isImported('rate_limit_capacity')}<span class="imported-badge">imported</span>{/if}
      <input id="rate-limit-capacity" type="number" min="0" max="1000000" bind:value={form.rate_limit_capacity} placeholder="Disabled" />
      <span class="hint">Burst size. 0 disables.</span>
    </div>
    <div class="form-group" class:modified={isModified('rate_limit_refill_per_sec')}>
      <label for="rate-limit-refill">Refill (tokens/s)</label>
      {#if isImported('rate_limit_refill_per_sec')}<span class="imported-badge">imported</span>{/if}
      <input id="rate-limit-refill" type="number" min="0" max="1000000" bind:value={form.rate_limit_refill_per_sec} placeholder="0 = one-shot" />
      <span class="hint">Steady-state rate. 0 = bucket drains and does not refill.</span>
    </div>
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={isModified('rate_limit_scope')}>
      <label for="rate-limit-scope">Scope</label>
      {#if isImported('rate_limit_scope')}<span class="imported-badge">imported</span>{/if}
      <select id="rate-limit-scope" bind:value={form.rate_limit_scope}>
        <option value="per_ip">Per client IP (default)</option>
        <option value="per_route">Per route (shared across all clients)</option>
      </select>
      <span class="hint">
        Per-IP isolates abusive clients; per-route caps aggregate traffic to the origin.
      </span>
    </div>
  </div>

  <div class="section-divider">
    <h4>GeoIP country filter <span class="hint">(per route)</span></h4>
    <p class="section-hint">
      Resolves the client IP to an ISO 3166-1 alpha-2 country code via the
      <code>.mmdb</code> database configured in Settings. Allowlist = only listed
      countries pass; denylist = listed countries are rejected (403). Unknown
      country (reserved / private IP, DB miss) falls through without blocking;
      layer <code>ip_allowlist</code> on top for fail-close semantics. Requires
      <code>geoip_db_path</code> set globally.
    </p>
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={isModified('geoip_mode')}>
      <label for="geoip-mode">Mode</label>
      {#if isImported('geoip_mode')}<span class="imported-badge">imported</span>{/if}
      <select id="geoip-mode" bind:value={form.geoip_mode}>
        <option value="denylist">Denylist (block listed countries)</option>
        <option value="allowlist">Allowlist (block everything except listed)</option>
      </select>
      <span class="hint">
        Empty country list in denylist mode = filter disabled for this route.
        Allowlist with empty list is rejected by the API (would block
        everything).
      </span>
    </div>
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={isModified('geoip_countries')}>
      <label for="geoip-countries">Countries <span class="hint">(ISO 3166-1 alpha-2, comma-separated)</span></label>
      {#if isImported('geoip_countries')}<span class="imported-badge">imported</span>{/if}
      <input
        id="geoip-countries"
        type="text"
        bind:value={form.geoip_countries}
        placeholder="e.g. FR, DE, IT"
        autocomplete="off"
      />
      <span class="hint">
        Codes normalised to uppercase, duplicates collapsed. Max 300 entries.
      </span>
    </div>
  </div>

  <div class="section-divider">
    <h4>Bot protection <span class="hint">(per route)</span></h4>
    <p class="section-hint">
      Graded challenge gate evaluated after GeoIP and before forward_auth.
      Three modes in increasing friction: <strong>Cookie</strong> (passive,
      catches scripts that do not persist cookies), <strong>JavaScript</strong>
      (SHA-256 proof-of-work, ~50 ms to ~12 s on the client depending on
      difficulty), <strong>Captcha</strong> (image + text, human interaction).
      Bypass rules (IP CIDRs / countries / User-Agent regex) short-circuit the
      challenge; first match wins. <code>only_country</code> inverse gate fires
      the challenge only for the listed countries — leave empty to challenge
      every request. See <code>docs/architecture/bot-protection.md</code> for
      the full design + threat model.
    </p>
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={isModified('bot_enabled')}>
      <label>
        {#if isImported('bot_enabled')}<span class="imported-badge">imported</span>{/if}
        <input type="checkbox" bind:checked={form.bot_enabled} />
        Enable bot protection
      </label>
      <span class="hint">
        Off = skip the bot-protection stage entirely for this route.
      </span>
    </div>
  </div>

  {#if form.bot_enabled}
    <div class="form-row">
      <div class="form-group" class:modified={isModified('bot_mode')}>
        <label for="bot-mode">Mode</label>
        {#if isImported('bot_mode')}<span class="imported-badge">imported</span>{/if}
        <select id="bot-mode" bind:value={form.bot_mode}>
          <option value="cookie">Cookie (passive, zero UX cost)</option>
          <option value="javascript">JavaScript PoW (default)</option>
          <option value="captcha">Captcha (image, human interaction)</option>
        </select>
      </div>
      <div class="form-group" class:modified={isModified('bot_cookie_ttl_s')}>
        <label for="bot-cookie-ttl">Cookie TTL <span class="hint">(seconds, 1&hellip;604800)</span></label>
        {#if isImported('bot_cookie_ttl_s')}<span class="imported-badge">imported</span>{/if}
        <input
          id="bot-cookie-ttl"
          type="number"
          min="1"
          max="604800"
          bind:value={form.bot_cookie_ttl_s}
        />
        <span class="hint">
          Default 86400 (24 h). API caps at 604800 = 7 days.
        </span>
      </div>
    </div>

    {#if form.bot_mode === 'javascript'}
      <div class="form-row">
        <div class="form-group" class:modified={isModified('bot_pow_difficulty')}>
          <label for="bot-pow">
            PoW difficulty <span class="hint">(leading zero bits, 14&hellip;22)</span>
          </label>
          {#if isImported('bot_pow_difficulty')}<span class="imported-badge">imported</span>{/if}
          <input
            id="bot-pow"
            type="range"
            min="14"
            max="22"
            bind:value={form.bot_pow_difficulty}
          />
          <span class="hint">
            Current: <strong>{form.bot_pow_difficulty} bits</strong> &mdash;
            expected median solve
            {#if form.bot_pow_difficulty <= 14}~50 ms
            {:else if form.bot_pow_difficulty <= 16}~200 ms
            {:else if form.bot_pow_difficulty <= 18}~800 ms (~2 s on mobile)
            {:else if form.bot_pow_difficulty <= 20}~3 s
            {:else}~12 s (UX degraded on mobile)
            {/if}
          </span>
        </div>
      </div>
    {/if}

    {#if form.bot_mode === 'captcha'}
      <div class="form-row">
        <div class="form-group" class:modified={isModified('bot_captcha_alphabet')}>
          <label for="bot-alphabet">Captcha alphabet</label>
          {#if isImported('bot_captcha_alphabet')}<span class="imported-badge">imported</span>{/if}
          <input
            id="bot-alphabet"
            type="text"
            bind:value={form.bot_captcha_alphabet}
            autocomplete="off"
            spellcheck="false"
          />
          <span class="hint">
            Default excludes confusables (<code>0/O/1/l/I</code>) and glyphs the
            bundled font does not render (<code>L/o</code>). Min 10 chars, max 128;
            ASCII printable only, no duplicates (all enforced by the API validator).
          </span>
        </div>
      </div>
    {/if}

    <div class="form-row">
      <div class="form-group" class:modified={isModified('bot_bypass_ip_cidrs')}>
        <label for="bot-bypass-ips">
          Bypass &mdash; IP CIDRs <span class="hint">(comma-separated)</span>
        </label>
        {#if isImported('bot_bypass_ip_cidrs')}<span class="imported-badge">imported</span>{/if}
        <input
          id="bot-bypass-ips"
          type="text"
          bind:value={form.bot_bypass_ip_cidrs}
          placeholder="e.g. 10.0.0.0/8, 2001:db8::/32"
          autocomplete="off"
        />
        <span class="hint">
          Office subnets, health-check probes. Max 500 entries.
        </span>
      </div>
    </div>

    <div class="form-row">
      <div class="form-group" class:modified={isModified('bot_bypass_countries')}>
        <label for="bot-bypass-countries">
          Bypass &mdash; Countries <span class="hint">(ISO 3166-1 alpha-2, comma-separated)</span>
        </label>
        {#if isImported('bot_bypass_countries')}<span class="imported-badge">imported</span>{/if}
        <input
          id="bot-bypass-countries"
          type="text"
          bind:value={form.bot_bypass_countries}
          placeholder="e.g. FR, DE"
          autocomplete="off"
        />
        <span class="hint">
          Requires a GeoIP database loaded (Settings &rarr; GeoIP).
        </span>
      </div>
    </div>

    <div class="form-row">
      <div class="form-group" class:modified={isModified('bot_bypass_user_agents')}>
        <label for="bot-bypass-ua">
          Bypass &mdash; User-Agent regexes <span class="hint">(one per line)</span>
        </label>
        {#if isImported('bot_bypass_user_agents')}<span class="imported-badge">imported</span>{/if}
        <textarea
          id="bot-bypass-ua"
          rows="4"
          bind:value={form.bot_bypass_user_agents}
          placeholder={'(?i)^Mozilla/5\\.0 .* Firefox/\n(?i)googlebot'}
          autocomplete="off"
          spellcheck="false"
        ></textarea>
        <span class="hint">
          Rust <code>regex</code> crate syntax (no lookahead, no backreference).
          Patterns compiled at API save time; a bad regex is rejected up front.
          Trivially spoofable on its own &mdash; pair with IP CIDRs or a future
          rDNS match.
        </span>
      </div>
    </div>

    <div class="form-row">
      <div class="form-group" class:modified={isModified('bot_only_country')}>
        <label for="bot-only-country">
          <code>only_country</code> gate <span class="hint">(comma-separated, empty = disabled)</span>
        </label>
        {#if isImported('bot_only_country')}<span class="imported-badge">imported</span>{/if}
        <input
          id="bot-only-country"
          type="text"
          bind:value={form.bot_only_country}
          placeholder="e.g. RU, CN"
          autocomplete="off"
        />
        <span class="hint">
          When set, the challenge fires <strong>only</strong> for these
          countries; everyone else passes through. Useful when protection is
          geo-targeted.
        </span>
      </div>
    </div>

    <p class="section-hint">
      <strong>ASN bypass</strong> and <strong>rDNS bypass</strong> are listed in
      the design doc but deferred to a v1.4.x follow-up: ASN needs a dedicated
      database distribution; rDNS needs a forward-confirmation DNS pipeline
      (design § 10.3 flags rDNS-without-forward-confirm as a must-not
      regression). The API rejects non-empty lists for both today.
    </p>
  {/if}
</div>

<style>
  .tab-content { display: flex; flex-direction: column; gap: 0; }

  .form-group { margin-bottom: 1rem; }
  .form-group.modified { border-left: 3px solid var(--color-primary); padding-left: 0.75rem; }

  .form-group label {
    display: block;
    font-size: 0.8125rem;
    font-weight: 500;
    color: var(--color-text-muted);
    margin-bottom: 0.375rem;
  }

  .form-group input[type="number"] {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
  }

  .form-group input:focus,
  .form-group select:focus { outline: none; border-color: var(--color-primary); }

  .form-group select {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
  }

  .section-divider {
    margin-top: 1.5rem;
    padding-top: 1rem;
    border-top: 1px solid var(--color-border);
  }
  .section-divider h4 {
    font-size: 0.875rem;
    font-weight: 600;
    color: var(--color-text);
    margin: 0 0 0.25rem 0;
  }
  .section-divider code {
    font-size: 0.75rem;
    padding: 0.0625rem 0.25rem;
    background: var(--color-bg-input);
    border-radius: 0.1875rem;
  }
  .section-hint {
    font-size: 0.75rem;
    color: var(--color-text-muted);
    margin: 0 0 1rem 0;
  }

  .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }

  .hint { font-weight: 400; color: var(--color-text-muted); font-size: 0.75rem; }

  .imported-badge {
    display: inline-block;
    padding: 0.0625rem 0.375rem;
    border-radius: 9999px;
    font-size: 0.625rem;
    font-weight: 600;
    text-transform: uppercase;
    background: rgba(59, 130, 246, 0.15);
    color: var(--color-primary);
    margin-left: 0.375rem;
    vertical-align: middle;
  }
</style>
