<script lang="ts">
  import type { RouteFormState } from '../../lib/route-form';
  import { ROUTE_DEFAULTS } from '../../lib/route-form';
  import CountryPicker from '../CountryPicker.svelte';
  import SubsectionHeader from '../SubsectionHeader.svelte';
  import FieldHelpButton from '../FieldHelpButton.svelte';
  import HelpModal from '../HelpModal.svelte';

  interface Props {
    form: RouteFormState;
    importedFields?: Set<string>;
  }

  let { form = $bindable(), importedFields }: Props = $props();

  let activeHelp = $state<
    | null
    | 'section:rate_limit'
    | 'section:connection_limits'
    | 'section:body_limit'
    | 'section:auto_ban'
    | 'section:geoip'
    | 'section:bot'
  >(null);

  function isModified(field: keyof RouteFormState): boolean {
    return ROUTE_DEFAULTS[field] !== form[field];
  }

  function isImported(field: string): boolean {
    return importedFields?.has(field) ?? false;
  }

  // Auto-ban only fires on WAF violations (lorica_waf::BanReason).
  // When WAF is disabled, any auto_ban settings become silent no-ops.
  // Surface this clearly rather than letting the operator configure
  // protection that never triggers.
  let autoBanDependsOnWaf = $derived(
    !form.waf_enabled &&
      (Number(form.auto_ban_threshold) > 0 || form.auto_ban_duration_s !== ROUTE_DEFAULTS.auto_ban_duration_s),
  );
</script>

<div class="tab-content">
  <!-- ============ Rate limit ============ -->
  <section id="prot-rate-limit" class="subsection">
    <SubsectionHeader
      title="Rate limit"
      description="Token bucket per client IP (or per route). Cross-worker synced with the supervisor every 100 ms under --workers N."
      accent="blue"
      onhelp={() => { activeHelp = 'section:rate_limit'; }}
    />
    <div class="subsection-body">
      <div class="form-row">
        <div class="form-group" class:modified={isModified('rate_limit_capacity')}>
          <label for="rate-limit-capacity">Capacity (burst tokens)</label>
          {#if isImported('rate_limit_capacity')}<span class="imported-badge">imported</span>{/if}
          <input id="rate-limit-capacity" type="number" min="0" max="1000000" bind:value={form.rate_limit_capacity} placeholder="Disabled" />
          <span class="hint">Burst size. 0 disables the rate limit entirely.</span>
        </div>
        <div class="form-group" class:modified={isModified('rate_limit_refill_per_sec')}>
          <label for="rate-limit-refill">Refill (tokens/s)</label>
          {#if isImported('rate_limit_refill_per_sec')}<span class="imported-badge">imported</span>{/if}
          <input id="rate-limit-refill" type="number" min="0" max="1000000" bind:value={form.rate_limit_refill_per_sec} placeholder="0 = one-shot" />
          <span class="hint">Steady-state rate. 0 = bucket drains and does not refill.</span>
        </div>
      </div>
      <div class="form-group" class:modified={isModified('rate_limit_scope')}>
        <label for="rate-limit-scope">Scope</label>
        {#if isImported('rate_limit_scope')}<span class="imported-badge">imported</span>{/if}
        <select id="rate-limit-scope" bind:value={form.rate_limit_scope}>
          <option value="per_ip">Per client IP (default)</option>
          <option value="per_route">Per route (shared across all clients)</option>
        </select>
        <span class="hint">Per-IP isolates abusive clients; per-route caps aggregate traffic to the origin.</span>
      </div>
    </div>
  </section>

  <!-- ============ Connection limits ============ -->
  <section id="prot-connection" class="subsection">
    <SubsectionHeader
      title="Connection limits"
      description="Caps concurrent connections and guards against slow-client (Slowloris) attacks."
      accent="cyan"
      onhelp={() => { activeHelp = 'section:connection_limits'; }}
    />
    <div class="subsection-body">
      <div class="form-row">
        <div class="form-group" class:modified={isModified('max_connections')}>
          <label for="max-connections">Max connections</label>
          {#if isImported('max_connections')}<span class="imported-badge">imported</span>{/if}
          <input id="max-connections" type="number" min="1" bind:value={form.max_connections} placeholder="No limit" />
          <span class="hint">Max concurrent connections for this route. Nginx: <code>limit_conn</code>.</span>
        </div>
        <div class="form-group" class:modified={isModified('slowloris_threshold_ms')}>
          <label for="slowloris-threshold">Slowloris threshold (ms)</label>
          {#if isImported('slowloris_threshold_ms')}<span class="imported-badge">imported</span>{/if}
          <input id="slowloris-threshold" type="number" min="100" bind:value={form.slowloris_threshold_ms} placeholder="5000" />
          <span class="hint">Abort a client that has not finished sending headers within this window.</span>
        </div>
      </div>
    </div>
  </section>

  <!-- ============ Body size limit ============ -->
  <section id="prot-body" class="subsection">
    <SubsectionHeader
      title="Body size limit"
      description="Max request body size this route accepts. Larger requests are rejected with 413 Payload Too Large."
      accent="purple"
      onhelp={() => { activeHelp = 'section:body_limit'; }}
    />
    <div class="subsection-body">
      <div class="form-group" class:modified={isModified('max_body_mb')}>
        <label for="max-body">Max body (MB)</label>
        {#if isImported('max_body_mb')}<span class="imported-badge">imported</span>{/if}
        <input id="max-body" type="number" min="0" step="1" bind:value={form.max_body_mb} placeholder="No limit" />
        <span class="hint">0 or empty = no limit. Nginx equivalent: <code>client_max_body_size</code>.</span>
      </div>
    </div>
  </section>

  <!-- ============ Auto-ban ============ -->
  <section id="prot-auto-ban" class="subsection">
    <SubsectionHeader
      title="Auto-ban"
      description="Temporarily ban a client IP after N WAF violations. Fail2ban-like, built into the proxy."
      accent="red"
      onhelp={() => { activeHelp = 'section:auto_ban'; }}
    />
    <div class="subsection-body">
      {#if autoBanDependsOnWaf}
        <div class="warn-banner" role="note">
          <strong>Auto-ban fires on WAF violations only.</strong>
          This route has auto-ban settings but WAF is disabled (see
          Security tab). These values are currently no-ops. Enable WAF
          to activate auto-ban, or clear these values to avoid
          confusion.
        </div>
      {/if}
      <div class="form-row">
        <div class="form-group" class:modified={isModified('auto_ban_threshold')}>
          <label for="auto-ban-threshold">Threshold (violations before ban)</label>
          {#if isImported('auto_ban_threshold')}<span class="imported-badge">imported</span>{/if}
          <input id="auto-ban-threshold" type="number" min="1" bind:value={form.auto_ban_threshold} placeholder="Disabled" />
          <span class="hint">Empty or 0 = auto-ban disabled.</span>
        </div>
        <div class="form-group" class:modified={isModified('auto_ban_duration_s')}>
          <label for="auto-ban-duration">Duration (s)</label>
          {#if isImported('auto_ban_duration_s')}<span class="imported-badge">imported</span>{/if}
          <input id="auto-ban-duration" type="number" min="1" bind:value={form.auto_ban_duration_s} placeholder="3600" />
          <span class="hint">Ban duration after the threshold is hit.</span>
        </div>
      </div>
    </div>
  </section>

  <!-- ============ GeoIP country filter ============ -->
  <section id="prot-geoip" class="subsection">
    <SubsectionHeader
      title="GeoIP country filter"
      description="Allow or deny by ISO 3166-1 country resolved from the client IP. Requires a GeoIP .mmdb loaded in Settings."
      accent="orange"
      onhelp={() => { activeHelp = 'section:geoip'; }}
    />
    <div class="subsection-body">
      <div class="form-group" class:modified={isModified('geoip_mode')}>
        <label for="geoip-mode">Mode</label>
        {#if isImported('geoip_mode')}<span class="imported-badge">imported</span>{/if}
        <select id="geoip-mode" bind:value={form.geoip_mode}>
          <option value="denylist">Denylist (block listed countries)</option>
          <option value="allowlist">Allowlist (block everything except listed)</option>
        </select>
        <span class="hint">Empty list + denylist = filter off. Empty list + allowlist = rejected by API.</span>
      </div>
      <div class="form-group" class:modified={isModified('geoip_countries')}>
        {#if isImported('geoip_countries')}<span class="imported-badge">imported</span>{/if}
        <CountryPicker
          label="Countries"
          bind:value={form.geoip_countries}
          hint="Click a country on the map to toggle. Codes normalised to uppercase, duplicates collapsed. Max 300 entries."
        />
      </div>
    </div>
  </section>

  <!-- ============ Bot protection ============ -->
  <section id="prot-bot" class="subsection">
    <SubsectionHeader
      title="Bot protection"
      description="Graded challenge gate: Cookie (passive) / JavaScript PoW / Captcha. Five bypass categories (IP / ASN / country / User-Agent regex / rDNS)."
      accent="pink"
      onhelp={() => { activeHelp = 'section:bot'; }}
    />
    <div class="subsection-body">
      <div class="form-group" class:modified={isModified('bot_enabled')}>
        <label class="checkbox-item">
          <input type="checkbox" bind:checked={form.bot_enabled} />
          <span>Enable bot protection</span>
        </label>
        {#if isImported('bot_enabled')}<span class="imported-badge">imported</span>{/if}
        <span class="hint">Off = skip the bot-protection stage entirely for this route.</span>
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
            <label for="bot-cookie-ttl">Cookie TTL (seconds, 1..604800)</label>
            {#if isImported('bot_cookie_ttl_s')}<span class="imported-badge">imported</span>{/if}
            <input id="bot-cookie-ttl" type="number" min="1" max="604800" bind:value={form.bot_cookie_ttl_s} />
            <span class="hint">Default 86400 (24 h). API caps at 604800 = 7 days.</span>
          </div>
        </div>

        {#if form.bot_mode === 'javascript'}
          <div class="form-group" class:modified={isModified('bot_pow_difficulty')}>
            <label for="bot-pow">PoW difficulty (leading zero bits, 14..22)</label>
            {#if isImported('bot_pow_difficulty')}<span class="imported-badge">imported</span>{/if}
            <input id="bot-pow" type="range" min="14" max="22" bind:value={form.bot_pow_difficulty} />
            <span class="hint">
              Current: <strong>{form.bot_pow_difficulty} bits</strong> - expected median solve
              {#if form.bot_pow_difficulty <= 14}~50 ms
              {:else if form.bot_pow_difficulty <= 16}~200 ms
              {:else if form.bot_pow_difficulty <= 18}~800 ms (~2 s on mobile)
              {:else if form.bot_pow_difficulty <= 20}~3 s
              {:else}~12 s (UX degraded on mobile)
              {/if}
            </span>
          </div>
        {/if}

        {#if form.bot_mode === 'captcha'}
          <div class="form-group" class:modified={isModified('bot_captcha_alphabet')}>
            <label for="bot-alphabet">Captcha alphabet</label>
            {#if isImported('bot_captcha_alphabet')}<span class="imported-badge">imported</span>{/if}
            <input id="bot-alphabet" type="text" bind:value={form.bot_captcha_alphabet} autocomplete="off" spellcheck="false" />
            <span class="hint">Default excludes confusables (<code>0/O/1/l/I</code>) and glyphs the bundled font cannot render (<code>L/o</code>). Min 10, max 128 ASCII printable, no duplicates.</span>
          </div>
        {/if}

        <div class="form-group" class:modified={isModified('bot_bypass_ip_cidrs')}>
          <label for="bot-bypass-ips">Bypass - IP CIDRs</label>
          {#if isImported('bot_bypass_ip_cidrs')}<span class="imported-badge">imported</span>{/if}
          <input id="bot-bypass-ips" type="text" bind:value={form.bot_bypass_ip_cidrs} placeholder="e.g. 10.0.0.0/8, 2001:db8::/32" autocomplete="off" />
          <span class="hint">Comma-separated. Office subnets, health-check probes. Max 500 entries.</span>
        </div>

        <div class="form-group" class:modified={isModified('bot_bypass_asns')}>
          <label for="bot-bypass-asns">Bypass - ASNs</label>
          {#if isImported('bot_bypass_asns')}<span class="imported-badge">imported</span>{/if}
          <input id="bot-bypass-asns" type="text" bind:value={form.bot_bypass_asns} placeholder="e.g. 15169, 13335" autocomplete="off" />
          <span class="hint">Comma-separated, <code>AS</code> prefix optional. Requires an ASN database loaded (Settings &rarr; Network). ASN 0 is IANA-reserved and rejected.</span>
        </div>

        <div class="form-group" class:modified={isModified('bot_bypass_countries')}>
          {#if isImported('bot_bypass_countries')}<span class="imported-badge">imported</span>{/if}
          <CountryPicker
            label="Bypass - Countries"
            bind:value={form.bot_bypass_countries}
            hint="Click a country on the map to allow-list it. Requires a GeoIP database loaded."
          />
        </div>

        <div class="form-group" class:modified={isModified('bot_bypass_user_agents')}>
          <label for="bot-bypass-ua">Bypass - User-Agent regexes</label>
          {#if isImported('bot_bypass_user_agents')}<span class="imported-badge">imported</span>{/if}
          <textarea id="bot-bypass-ua" rows="4" bind:value={form.bot_bypass_user_agents}
            placeholder={'(?i)^Mozilla/5\\.0 .* Firefox/\n(?i)googlebot'}
            autocomplete="off" spellcheck="false"></textarea>
          <span class="hint">
            Rust <code>regex</code> crate syntax (no lookahead, no backreference). One per line. Trivially spoofable alone - pair with IP CIDRs or rDNS.
          </span>
        </div>

        <div class="form-group" class:modified={isModified('bot_bypass_rdns')}>
          <label for="bot-bypass-rdns">Bypass - rDNS suffixes</label>
          {#if isImported('bot_bypass_rdns')}<span class="imported-badge">imported</span>{/if}
          <textarea id="bot-bypass-rdns" rows="3" bind:value={form.bot_bypass_rdns}
            placeholder={'googlebot.com\nsearch.msn.com'}
            autocomplete="off" spellcheck="false"></textarea>
          <span class="hint">
            Domain suffixes matched against the client IP's PTR record. Forward confirmation is enforced: the PTR name must resolve back to the client IP (A/AAAA match). Lookups are async with a 1 h cache.
          </span>
        </div>

        <div class="form-group" class:modified={isModified('bot_only_country')}>
          {#if isImported('bot_only_country')}<span class="imported-badge">imported</span>{/if}
          <CountryPicker
            label="only_country gate (empty = disabled)"
            bind:value={form.bot_only_country}
            hint="Click a country to restrict the challenge to its traffic. When set, the challenge fires ONLY for these countries; everyone else passes through."
          />
        </div>
      {/if}
    </div>
  </section>
</div>

{#if activeHelp === 'section:rate_limit'}
  <HelpModal title="Rate limit" onclose={() => { activeHelp = null; }}>
    <p>
      Token-bucket rate limit per client IP (default) or per route.
      Every incoming request consumes 1 token; the bucket refills at
      the configured steady rate. When the bucket is empty the request
      returns 429 with a <code>Retry-After</code> header.
    </p>
    <p><strong>Parameters</strong>:</p>
    <ul>
      <li><code>Capacity</code> - burst size. 4-10 is typical for
        interactive APIs; leave 0 to disable entirely.</li>
      <li><code>Refill per second</code> - steady-state rate. A
        capacity-10 bucket with refill-2 allows bursts up to 10 and
        a sustained 2 RPS.</li>
      <li><code>Scope</code> - <em>Per-IP</em> isolates abusive
        clients (one busy client does not affect others); <em>Per
        route</em> caps aggregate traffic reaching the origin
        (protects a fragile backend).</li>
    </ul>
    <p>
      Cross-worker synced: every 100 ms each worker's local bucket
      reconciles with the supervisor's authoritative state, so the
      limit holds globally under <code>--workers N</code>.
    </p>
  </HelpModal>
{:else if activeHelp === 'section:connection_limits'}
  <HelpModal title="Connection limits" onclose={() => { activeHelp = null; }}>
    <p>
      Caps concurrent connections and guards against slow-client
      attacks.
    </p>
    <ul>
      <li>
        <strong>Max connections</strong>: hard cap on concurrent
        connections this route is allowed to hold. Further clients
        receive 503. Useful when a backend saturates at a known
        concurrency (e.g. database connection pool size).
      </li>
      <li>
        <strong>Slowloris threshold</strong>: time budget a client has
        to finish sending the request headers. Clients that drip
        bytes beyond this window are disconnected; a classic
        Slowloris DoS pattern is blocked without touching the
        backend.
      </li>
    </ul>
    <p>
      Both run at the L7 layer. For network-level accept-time
      filtering (deny whole CIDRs before TLS), see the global
      <code>connection_deny_cidrs</code> in Settings &rarr; Network.
    </p>
  </HelpModal>
{:else if activeHelp === 'section:body_limit'}
  <HelpModal title="Body size limit" onclose={() => { activeHelp = null; }}>
    <p>
      Maximum request body Lorica will buffer and forward to the
      backend for this route. Exceeding requests are rejected at
      <code>request_filter</code> with a 413 Payload Too Large.
    </p>
    <p>
      Set this even when your backend has its own limit: Lorica
      rejects the oversize request before it hits the upstream, saving
      CPU / bandwidth and preventing slow-write DoS on big bodies.
    </p>
    <p>
      Leave empty (or 0) for no limit - appropriate for upload
      endpoints where the backend decides. Set a small value
      (e.g. 1 MB) for routes that only accept JSON control commands.
    </p>
    <p>
      Nginx equivalent: <code>client_max_body_size</code>.
      Traefik: <code>Buffering.maxRequestBodyBytes</code>.
    </p>
  </HelpModal>
{:else if activeHelp === 'section:auto_ban'}
  <HelpModal title="Auto-ban" onclose={() => { activeHelp = null; }}>
    <p>
      Temporarily bans a client IP after it has triggered a configured
      number of WAF violations. Acts like fail2ban but runs inside the
      proxy, not as a separate daemon writing iptables rules.
    </p>
    <p><strong>Important dependency</strong>: this feature relies on
    WAF violations as its trigger signal. With WAF disabled (Security
    tab), the WAF never flags anything, so <code>auto_ban_threshold</code>
    is a silent no-op. A warning banner shows when this mis-configuration
    is detected.</p>
    <p>
      Bans are per-route, cached in memory, and cleared on a restart.
      For durable bans across restarts, export / import via the
      management API or rely on an external fail2ban setup.
    </p>
  </HelpModal>
{:else if activeHelp === 'section:geoip'}
  <HelpModal title="GeoIP country filter" onclose={() => { activeHelp = null; }}>
    <p>
      Accepts or rejects requests based on the client IP's country,
      resolved via a <code>.mmdb</code> database loaded globally in
      Settings &rarr; Network.
    </p>
    <p><strong>Modes</strong>:</p>
    <ul>
      <li><em>Denylist</em>: listed countries are rejected with 403,
        everything else passes. Good default for blocking known
        abuse regions.</li>
      <li><em>Allowlist</em>: only listed countries pass, everything
        else is rejected with 403. Good default when your audience
        is geographically constrained (ex: regional SaaS).</li>
    </ul>
    <p>
      <strong>Fail-open on unknowns</strong>: reserved / private IPs
      and DB misses fall through without blocking (denied country =
      "unknown" would otherwise block a corporate NAT by accident).
      For fail-closed semantics, layer <code>ip_allowlist</code>
      (Security tab) on top.
    </p>
    <p>
      Data sources: DB-IP Lite Country (CC-BY 4.0, monthly refresh,
      free) or MaxMind GeoLite2 (account required, weekly refresh).
      Auto-update is enabled from Settings &rarr; Network.
    </p>
  </HelpModal>
{:else if activeHelp === 'section:bot'}
  <HelpModal title="Bot protection" onclose={() => { activeHelp = null; }}>
    <p>
      A graded challenge gate that filters automated traffic. Three
      modes with increasing friction:
    </p>
    <ul>
      <li><strong>Cookie</strong> - passive redirect that sets a
        verdict cookie. Zero UX cost for real browsers, catches
        scripts that do not persist cookies.</li>
      <li><strong>JavaScript PoW</strong> (default) - SHA-256 proof of
        work executed client-side. Configurable difficulty from ~50 ms
        to ~12 s; 18 bits is the sweet spot (~800 ms median).</li>
      <li><strong>Captcha</strong> - image + text form. Human
        interaction required; friction of last resort.</li>
    </ul>
    <p>
      Evaluated after GeoIP and before Forward auth. Five bypass
      categories short-circuit the challenge (first match wins):
      IP CIDR, ASN, country, User-Agent regex, and rDNS suffix (with
      mandatory forward-confirmation to prevent PTR spoofing).
    </p>
    <p>
      The <code>only_country</code> inverse gate fires the challenge
      only for the listed countries; leave empty to challenge every
      request. Useful when the protection is geo-targeted.
    </p>
    <p>
      Full design in <code>docs/architecture/bot-protection.md</code>
      (threat model, wire format, captcha alphabet defaults).
    </p>
  </HelpModal>
{/if}

<style>
  .tab-content { display: flex; flex-direction: column; gap: 1.25rem; }

  .subsection {
    display: flex;
    flex-direction: column;
    border-radius: 0.5rem;
    overflow: hidden;
  }

  .subsection-body {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-top: none;
    border-radius: 0 0 0.5rem 0.5rem;
    padding: 1rem 1rem 0.5rem;
  }

  .warn-banner {
    margin-bottom: 1rem;
    padding: 0.5rem 0.75rem;
    background: rgba(245, 158, 11, 0.08);
    border-left: 3px solid var(--color-orange, #f59e0b);
    border-radius: 0 0.25rem 0.25rem 0;
    font-size: 0.8125rem;
    color: var(--color-text);
    line-height: 1.45;
  }
  .warn-banner strong { color: var(--color-text-heading); }

  .form-group { margin-bottom: 1rem; }
  .form-group:last-child { margin-bottom: 0.5rem; }
  .form-group.modified { border-left: 3px solid var(--color-primary); padding-left: 0.75rem; }

  .form-group label {
    display: block;
    font-size: 0.8125rem;
    font-weight: 500;
    color: var(--color-text-muted);
    margin-bottom: 0.375rem;
  }

  .form-group input[type="text"],
  .form-group input[type="number"],
  .form-group select {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
  }

  .form-group input[type="range"] {
    width: 100%;
  }

  .form-group textarea {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.8125rem;
    font-family: var(--font-mono, ui-monospace, monospace);
    resize: vertical;
  }

  .form-group input:focus,
  .form-group select:focus,
  .form-group textarea:focus { outline: none; border-color: var(--color-primary); }

  .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }

  .checkbox-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    cursor: pointer;
  }
  .checkbox-item input[type="checkbox"] { accent-color: var(--color-primary); }

  .hint { display: block; font-weight: 400; color: var(--color-text-muted); font-size: 0.75rem; margin-top: 0.25rem; }

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
