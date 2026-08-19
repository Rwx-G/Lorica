<script lang="ts">
  import type { RouteFormState } from '../../lib/route-form';
  import { ROUTE_DEFAULTS } from '../../lib/route-form';
  import { api, type AiCrawlerTestResponse, type AiCrawlerStatEntry, type AiCrawlerVerificationKind } from '../../lib/api';
  import { verificationKindLabel } from '../../lib/ai-crawlers';
  import CountryPicker from '../CountryPicker.svelte';
  import SubsectionHeader from '../SubsectionHeader.svelte';
  import FieldHelpButton from '../FieldHelpButton.svelte';
  import HelpModal from '../HelpModal.svelte';
  import ChipListInput from '../ChipListInput.svelte';
  import { validateCidr, validateAsn, validateDnsSuffix } from '../../lib/validators';

  interface Props {
    form: RouteFormState;
    importedFields?: Set<string>;
    /**
     * The persisted route id, or `null` for an unsaved (new) route.
     * Required by the AI-crawler test / stats / robots-preview calls,
     * which evaluate against the stored route config. When absent the
     * widgets show a "save the route first" hint instead.
     */
    routeId?: string | null;
  }

  let { form = $bindable(), importedFields, routeId = null }: Props = $props();

  function aiPolicyLabel(policy: 'off' | 'deny' | 'log'): string {
    return policy === 'off' ? 'Off' : policy === 'deny' ? 'Deny' : 'Log';
  }

  // AI crawler "Test classification" widget state.
  let aiTestUa = $state('');
  let aiTestResult = $state<AiCrawlerTestResponse | null>(null);
  let aiTestError = $state<string | null>(null);
  let aiTestLoading = $state(false);
  async function runAiTest(): Promise<void> {
    const ua = aiTestUa.trim();
    if (ua === '') {
      aiTestError = 'Enter a User-Agent string to test.';
      aiTestResult = null;
      return;
    }
    aiTestLoading = true;
    aiTestError = null;
    const res = await api.testAiCrawler(ua, routeId);
    if (res.error) {
      aiTestError = res.error.message;
      aiTestResult = null;
    } else {
      aiTestResult = res.data ?? null;
    }
    aiTestLoading = false;
  }

  // "Detected crawlers" widget state (5-minute window, loaded on demand).
  let aiStats = $state<AiCrawlerStatEntry[] | null>(null);
  let aiStatsError = $state<string | null>(null);
  let aiStatsLoading = $state(false);
  async function loadAiStats(): Promise<void> {
    if (!routeId) return;
    aiStatsLoading = true;
    aiStatsError = null;
    const res = await api.getAiCrawlerStats(routeId);
    if (res.error) {
      aiStatsError = res.error.message;
      aiStats = null;
    } else {
      aiStats = res.data?.top_5 ?? [];
    }
    aiStatsLoading = false;
  }

  // robots.txt preview modal state.
  let showRobotsPreview = $state(false);
  let robotsPreviewBody = $state<string | null>(null);
  let robotsPreviewError = $state<string | null>(null);
  let robotsPreviewLoading = $state(false);
  async function openRobotsPreview(): Promise<void> {
    if (!routeId) return;
    showRobotsPreview = true;
    robotsPreviewLoading = true;
    robotsPreviewError = null;
    robotsPreviewBody = null;
    const res = await api.getAiCrawlerRobotsPreview(routeId);
    if (res.error) {
      robotsPreviewError = res.error.message;
    } else {
      robotsPreviewBody = res.data?.body ?? '';
    }
    robotsPreviewLoading = false;
  }

  function aiVerificationLabel(kind: AiCrawlerVerificationKind | null): string {
    return kind === null ? 'none' : verificationKindLabel(kind);
  }

  // Multi-line placeholder: HTML attributes render `\n` as two chars,
  // so the newline has to come from a JS string at interpolation time.
  // Hoisted to a const so eslint-svelte's `no-useless-mustaches` does
  // not flag the mustache expression as trivially replaceable.
  const UA_BYPASS_PLACEHOLDER = '(?i)^Mozilla/5\\.0 .* Firefox/\n(?i)googlebot';

  let activeHelp = $state<
    | null
    | 'section:rate_limit'
    | 'section:connection_limits'
    | 'section:body_limit'
    | 'section:auto_ban'
    | 'section:geoip'
    | 'section:bot'
    | 'section:ai_crawler'
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

  // Numeric-range blur validators. The API enforces the same bounds
  // via `validate_route_numeric_bounds`; these catch the mistake
  // before the operator hits Save.
  function rangeErr(raw: string | number, min: number, max: number, label: string): string | null {
    const str = String(raw).trim();
    if (str === '') return null;
    const n = Number(str);
    if (!Number.isInteger(n) || n < min || n > max) {
      return `${label} must be an integer in ${min}..${max}`;
    }
    return null;
  }
  let rateLimitCapacityError = $state<string | null>(null);
  let rateLimitRefillError = $state<string | null>(null);
  function checkRateLimitCapacity() { rateLimitCapacityError = rangeErr(form.rate_limit_capacity, 0, 1_000_000, 'value'); }
  function checkRateLimitRefill() { rateLimitRefillError = rangeErr(form.rate_limit_refill_per_sec, 0, 1_000_000, 'value'); }
  let maxConnError = $state<string | null>(null);
  let slowlorisError = $state<string | null>(null);
  let maxBodyError = $state<string | null>(null);
  let autoBanThresholdError = $state<string | null>(null);
  let autoBanDurationError = $state<string | null>(null);
  let botCookieTtlError = $state<string | null>(null);
  function checkMaxConn() { maxConnError = rangeErr(form.max_connections, 1, 1_000_000, 'value'); }
  function checkSlowloris() { slowlorisError = rangeErr(form.slowloris_threshold_ms, 100, 600_000, 'value'); }
  function checkMaxBody() {
    const raw = String(form.max_body_mb).trim();
    if (raw === '') { maxBodyError = null; return; }
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 0 || n > 131_072) {
      maxBodyError = 'value must be an integer in 0..131072 (0 = no limit)';
    } else {
      maxBodyError = null;
    }
  }
  function checkAutoBanThreshold() { autoBanThresholdError = rangeErr(form.auto_ban_threshold, 1, 10_000, 'value'); }
  function checkAutoBanDuration() { autoBanDurationError = rangeErr(form.auto_ban_duration_s, 1, 31_536_000, 'value'); }
  function checkBotCookieTtl() { botCookieTtlError = rangeErr(form.bot_cookie_ttl_s, 1, 604_800, 'value'); }
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
          <input id="rate-limit-capacity" type="number" min="0" max="1000000" bind:value={form.rate_limit_capacity} placeholder="Disabled" onblur={checkRateLimitCapacity} oninput={checkRateLimitCapacity} />
          {#if rateLimitCapacityError}<span class="field-error" role="alert">{rateLimitCapacityError}</span>{/if}
          <span class="hint">Burst size. 0 disables the rate limit entirely.</span>
        </div>
        <div class="form-group" class:modified={isModified('rate_limit_refill_per_sec')}>
          <label for="rate-limit-refill">Refill (tokens/s)</label>
          {#if isImported('rate_limit_refill_per_sec')}<span class="imported-badge">imported</span>{/if}
          <input id="rate-limit-refill" type="number" min="0" max="1000000" bind:value={form.rate_limit_refill_per_sec} placeholder="0 = one-shot" onblur={checkRateLimitRefill} oninput={checkRateLimitRefill} />
          {#if rateLimitRefillError}<span class="field-error" role="alert">{rateLimitRefillError}</span>{/if}
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
          <input id="max-connections" type="number" min="1" max="1000000" bind:value={form.max_connections} placeholder="No limit" onblur={checkMaxConn} oninput={checkMaxConn} />
          {#if maxConnError}<span class="field-error" role="alert">{maxConnError}</span>{/if}
          <span class="hint">Max concurrent connections for this route. Nginx: <code>limit_conn</code>.</span>
        </div>
        <div class="form-group" class:modified={isModified('slowloris_threshold_ms')}>
          <label for="slowloris-threshold">Slowloris threshold (ms)</label>
          {#if isImported('slowloris_threshold_ms')}<span class="imported-badge">imported</span>{/if}
          <input id="slowloris-threshold" type="number" min="100" max="600000" bind:value={form.slowloris_threshold_ms} placeholder="5000" onblur={checkSlowloris} oninput={checkSlowloris} />
          {#if slowlorisError}<span class="field-error" role="alert">{slowlorisError}</span>{/if}
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
        <input id="max-body" type="number" min="0" max="131072" step="1" bind:value={form.max_body_mb} placeholder="No limit" onblur={checkMaxBody} oninput={checkMaxBody} />
        {#if maxBodyError}<span class="field-error" role="alert">{maxBodyError}</span>{/if}
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
          <input id="auto-ban-threshold" type="number" min="1" max="10000" bind:value={form.auto_ban_threshold} placeholder="Disabled" onblur={checkAutoBanThreshold} oninput={checkAutoBanThreshold} />
          {#if autoBanThresholdError}<span class="field-error" role="alert">{autoBanThresholdError}</span>{/if}
          <span class="hint">Empty or 0 = auto-ban disabled.</span>
        </div>
        <div class="form-group" class:modified={isModified('auto_ban_duration_s')}>
          <label for="auto-ban-duration">Duration (s)</label>
          {#if isImported('auto_ban_duration_s')}<span class="imported-badge">imported</span>{/if}
          <input id="auto-ban-duration" type="number" min="1" max="31536000" bind:value={form.auto_ban_duration_s} placeholder="3600" onblur={checkAutoBanDuration} oninput={checkAutoBanDuration} />
          {#if autoBanDurationError}<span class="field-error" role="alert">{autoBanDurationError}</span>{/if}
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
            <input id="bot-cookie-ttl" type="number" min="1" max="604800" bind:value={form.bot_cookie_ttl_s} onblur={checkBotCookieTtl} oninput={checkBotCookieTtl} />
            {#if botCookieTtlError}<span class="field-error" role="alert">{botCookieTtlError}</span>{/if}
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
        {:else}
          <!-- Ghost hint: the PoW difficulty slider exists but only
               applies to JavaScript mode. Surface its presence so an
               operator scrolling Cookie / Captcha mode does not think
               it is missing. -->
          <div class="form-group ghost-hint" aria-hidden="true">
            <!-- Cosmetic label for a mode-gated control that is not
                 rendered here ; parent is aria-hidden so the label
                 is skipped by assistive tech. -->
            <!-- svelte-ignore a11y_label_has_associated_control -->
            <label>PoW difficulty</label>
            <span class="hint">Available after selecting JavaScript mode above.</span>
          </div>
        {/if}

        {#if form.bot_mode === 'captcha'}
          <div class="form-group" class:modified={isModified('bot_captcha_alphabet')}>
            <label for="bot-alphabet">Captcha alphabet</label>
            {#if isImported('bot_captcha_alphabet')}<span class="imported-badge">imported</span>{/if}
            <input id="bot-alphabet" type="text" bind:value={form.bot_captcha_alphabet} autocomplete="off" spellcheck="false" />
            <span class="hint">Default excludes confusables (<code>0/O/1/l/I</code>) and glyphs the bundled font cannot render (<code>L/o</code>). Min 10, max 128 ASCII printable, no duplicates.</span>
          </div>
        {:else}
          <div class="form-group ghost-hint" aria-hidden="true">
            <!-- Cosmetic label for a mode-gated control that is not
                 rendered here ; parent is aria-hidden so the label
                 is skipped by assistive tech. -->
            <!-- svelte-ignore a11y_label_has_associated_control -->
            <label>Captcha alphabet</label>
            <span class="hint">Available after selecting Captcha mode above.</span>
          </div>
        {/if}

        <div class="form-group" class:modified={isModified('bot_bypass_ip_cidrs')}>
          <label for="bot-bypass-ips">Bypass - IP CIDRs</label>
          {#if isImported('bot_bypass_ip_cidrs')}<span class="imported-badge">imported</span>{/if}
          <ChipListInput
            bind:value={form.bot_bypass_ip_cidrs}
            separator="csv"
            validator={validateCidr}
            placeholder="e.g. 10.0.0.0/8, 2001:db8::/32"
            ariaLabel="Bot bypass IP CIDR list"
          />
          <span class="hint">Office subnets, health-check probes. Press Enter or comma to add. Max 500 entries.</span>
        </div>

        <div class="form-group" class:modified={isModified('bot_bypass_asns')}>
          <label for="bot-bypass-asns">Bypass - ASNs</label>
          {#if isImported('bot_bypass_asns')}<span class="imported-badge">imported</span>{/if}
          <ChipListInput
            bind:value={form.bot_bypass_asns}
            separator="csv"
            validator={validateAsn}
            placeholder="e.g. 15169, 13335"
            ariaLabel="Bot bypass ASN list"
          />
          <span class="hint"><code>AS</code> prefix optional. Requires an ASN database loaded (Settings &rarr; Network). ASN 0 is IANA-reserved and rejected.</span>
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
            placeholder={UA_BYPASS_PLACEHOLDER}
            autocomplete="off" spellcheck="false"></textarea>
          <span class="hint">
            Rust <code>regex</code> crate syntax (no lookahead, no backreference). One per line. Trivially spoofable alone - pair with IP CIDRs or rDNS.
          </span>
        </div>

        <div class="form-group" class:modified={isModified('bot_bypass_rdns')}>
          <label for="bot-bypass-rdns">Bypass - rDNS suffixes</label>
          {#if isImported('bot_bypass_rdns')}<span class="imported-badge">imported</span>{/if}
          <ChipListInput
            bind:value={form.bot_bypass_rdns}
            separator="lines"
            validator={validateDnsSuffix}
            placeholder="e.g. googlebot.com, search.msn.com"
            ariaLabel="Bot bypass rDNS suffix list"
          />
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

  <!-- ============ AI crawler policy ============ -->
  <section id="prot-ai-crawler" class="subsection">
    <SubsectionHeader
      title="AI crawler policy"
      description="Identify verified AI crawlers (GPTBot, ClaudeBot, ...) and deny or log them. Spoofed bots (UA matches but verification fails) get a separate fallback action."
      accent="teal"
      onhelp={() => { activeHelp = 'section:ai_crawler'; }}
    />
    <div class="subsection-body">
      <div class="form-row">
        <div class="form-group" class:modified={isModified('ai_bot_policy')}>
          <label for="ai-bot-policy">Policy</label>
          {#if isImported('ai_bot_policy')}<span class="imported-badge">imported</span>{/if}
          <select id="ai-bot-policy" bind:value={form.ai_bot_policy}>
            <option value="off">Off (no AI crawler handling)</option>
            <option value="deny">Deny (block verified AI crawlers)</option>
            <option value="log">Log (record only, do not block)</option>
          </select>
          <span class="hint">Applies to crawlers whose identity is verified (rDNS / IP range).</span>
        </div>
        <div class="form-group" class:modified={isModified('ai_bot_spoofed_fallback')}>
          <label for="ai-bot-spoofed">Spoofed fallback</label>
          {#if isImported('ai_bot_spoofed_fallback')}<span class="imported-badge">imported</span>{/if}
          <select id="ai-bot-spoofed" bind:value={form.ai_bot_spoofed_fallback}>
            <option value="">Inherit global default</option>
            <option value="deny">Deny</option>
            <option value="log">Log</option>
            <option value="allow">Allow</option>
          </select>
          <span class="hint">Action when a UA claims to be an AI bot but verification fails. Inherit defers to the global setting.</span>
        </div>
      </div>

      <div class="form-group" class:modified={isModified('serve_robots_txt')}>
        <label class="checkbox-item">
          <input type="checkbox" bind:checked={form.serve_robots_txt} />
          <span>Auto-serve /robots.txt</span>
        </label>
        {#if isImported('serve_robots_txt')}<span class="imported-badge">imported</span>{/if}
        <span class="hint">
          ON = Lorica serves a registry-driven <code>robots.txt</code> for this route. OFF (default) = passes <code>/robots.txt</code> through to the backend.
        </span>
        <div class="ai-actions">
          <button type="button" class="ai-btn" onclick={openRobotsPreview} disabled={!routeId || robotsPreviewLoading}>
            {robotsPreviewLoading ? 'Loading...' : 'Preview robots.txt'}
          </button>
          {#if !routeId}<span class="hint inline-hint">Save the route first to preview.</span>{/if}
        </div>
      </div>

      <!-- Test classification -->
      <div class="form-group">
        <label for="ai-test-ua">Test classification</label>
        <div class="ai-inline-row">
          <input
            id="ai-test-ua"
            type="text"
            bind:value={aiTestUa}
            placeholder="Paste a User-Agent string"
            autocomplete="off"
            spellcheck="false"
          />
          <button type="button" class="ai-btn" onclick={runAiTest} disabled={aiTestLoading}>
            {aiTestLoading ? 'Testing...' : 'Test'}
          </button>
        </div>
        {#if aiTestError}<span class="field-error" role="alert">{aiTestError}</span>{/if}
        {#if aiTestResult}
          {#if aiTestResult.matched_crawler}
            <div class="ai-result">
              <strong>Matched:</strong> {aiTestResult.matched_crawler}
              <span class="ai-sep">;</span>
              <strong>Verification:</strong> {aiVerificationLabel(aiTestResult.verification_kind)}
              <span class="ai-sep">;</span>
              <strong>Would apply:</strong> {aiPolicyLabel(aiTestResult.would_apply_policy)}
            </div>
            {#if aiTestResult.note}<span class="hint">{aiTestResult.note}</span>{/if}
          {:else}
            <div class="ai-result ai-result-empty">No AI bot match{aiTestResult.note ? ` - ${aiTestResult.note}` : ''}</div>
          {/if}
        {/if}
        <span class="hint">Checks the UA against built-in and custom crawler patterns{routeId ? ' for this route' : ''}.</span>
      </div>

      <!-- Detected crawlers -->
      <div class="form-group">
        <label for="ai-stats-refresh">Detected crawlers (last 5 min)</label>
        <div class="ai-actions">
          <button id="ai-stats-refresh" type="button" class="ai-btn" onclick={loadAiStats} disabled={!routeId || aiStatsLoading}>
            {aiStatsLoading ? 'Loading...' : 'Refresh'}
          </button>
          {#if !routeId}<span class="hint inline-hint">Save the route first to see detected crawlers.</span>{/if}
        </div>
        {#if aiStatsError}<span class="field-error" role="alert">{aiStatsError}</span>{/if}
        {#if aiStats !== null}
          {#if aiStats.length === 0}
            <div class="ai-result ai-result-empty">No AI crawlers detected in the last 5 minutes.</div>
          {:else}
            <table class="ai-stats-table">
              <thead>
                <tr><th>Crawler</th><th>Hits</th></tr>
              </thead>
              <tbody>
                {#each aiStats as entry (entry.crawler)}
                  <tr>
                    <td>{entry.crawler}</td>
                    <td class="ai-count">{entry.count}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
        {/if}
      </div>
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
{:else if activeHelp === 'section:ai_crawler'}
  <HelpModal title="AI crawler policy" onclose={() => { activeHelp = null; }}>
    <p>
      Detects AI / LLM crawlers (GPTBot, ClaudeBot, Google-Extended,
      PerplexityBot, ...) from a built-in registry plus your custom
      entries (Settings &rarr; AI Crawlers), then applies a per-route
      action.
    </p>
    <p><strong>Policy</strong> - applied to crawlers whose identity is
    confirmed by their verification method (forward-confirmed rDNS or a
    published IP range):</p>
    <ul>
      <li><em>Off</em> - no AI-crawler handling for this route.</li>
      <li><em>Deny</em> - block the request (403).</li>
      <li><em>Log</em> - record the hit but let the request through.</li>
    </ul>
    <p>
      <strong>Spoofed fallback</strong> - a request whose User-Agent
      claims to be an AI bot but fails verification is treated
      separately, because anyone can copy a UA string. <em>Inherit</em>
      defers to the global default; <em>Deny</em> / <em>Log</em> /
      <em>Allow</em> pin a per-route action.
    </p>
    <p>
      <strong>Auto-serve /robots.txt</strong> - when ON, Lorica answers
      <code>/robots.txt</code> for this route with a registry-driven
      policy file instead of forwarding to the backend. OFF (default)
      passes the path through unchanged.
    </p>
    <p>
      Use <strong>Test classification</strong> to see how a given
      User-Agent would be classified, and <strong>Detected
      crawlers</strong> for a rolling 5-minute count of what hit this
      route.
    </p>
  </HelpModal>
{/if}

{#if showRobotsPreview}
  <HelpModal title="robots.txt preview" onclose={() => { showRobotsPreview = false; }}>
    {#if robotsPreviewLoading}
      <p>Loading...</p>
    {:else if robotsPreviewError}
      <p class="preview-error">{robotsPreviewError}</p>
    {:else}
      <p>Registry-driven <code>robots.txt</code> Lorica would serve for this route:</p>
      <pre>{robotsPreviewBody}</pre>
    {/if}
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

  /* Ghost placeholder for mode-dependent fields. Displayed grayed
     out when the sibling field is hidden behind a mode toggle, so
     an operator knows the field exists without flipping the toggle
     to find out. */
  .ghost-hint {
    opacity: 0.55;
    pointer-events: none;
  }
  .ghost-hint label {
    font-style: italic;
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
  .field-error { display: block; color: var(--color-red); font-size: var(--text-xs); margin-top: 0.25rem; }

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

  .ai-inline-row {
    display: flex;
    gap: 0.5rem;
    align-items: stretch;
  }
  .ai-inline-row input[type="text"] { flex: 1; }

  .ai-actions {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-top: 0.5rem;
  }
  .inline-hint { margin-top: 0; }

  .ai-btn {
    flex-shrink: 0;
    padding: 0.5rem 0.875rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.8125rem;
    font-weight: 500;
    cursor: pointer;
  }
  .ai-btn:hover:not(:disabled) { border-color: var(--color-primary); color: var(--color-primary); }
  .ai-btn:disabled { opacity: 0.55; cursor: not-allowed; }

  .ai-result {
    margin-top: 0.5rem;
    padding: 0.5rem 0.75rem;
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    border: 1px solid var(--color-border);
    font-size: 0.8125rem;
    line-height: 1.5;
  }
  .ai-result strong { color: var(--color-text-heading); }
  .ai-result-empty { color: var(--color-text-muted); }
  .ai-sep { color: var(--color-text-muted); margin: 0 0.25rem; }

  .ai-stats-table {
    width: 100%;
    margin-top: 0.5rem;
    border-collapse: collapse;
    font-size: 0.8125rem;
  }
  .ai-stats-table th {
    text-align: left;
    padding: 0.375rem 0.5rem;
    border-bottom: 1px solid var(--color-border);
    color: var(--color-text-muted);
    font-weight: 500;
    text-transform: uppercase;
    font-size: 0.6875rem;
    letter-spacing: 0.05em;
  }
  .ai-stats-table td {
    padding: 0.375rem 0.5rem;
    border-bottom: 1px solid var(--color-border);
  }
  .ai-count { text-align: right; font-variant-numeric: tabular-nums; }

  .preview-error { color: var(--color-red); }
</style>
