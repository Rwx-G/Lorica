// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Challenge-page rendering.
//!
//! Every mode returns a self-contained HTML document:
//! - **No external asset.** No CDN, no remote font, no `<script src>`.
//!   Air-gapped deployments must work unchanged.
//! - **Inline everything.** The CSS + the JavaScript PoW worker are
//!   embedded as `<style>` / `<script>` blocks so a single response
//!   is enough to run the challenge.
//! - **`<noscript>`** block explains how to contact the operator and
//!   never loads anything remotely — the fallback is static text.
//!
//! A plain-text fallback is rendered when the request's `Accept`
//! header does not advertise `text/html`: a short 403 body with a
//! one-line hint so a CLI tool sees a meaningful message instead of
//! a bag of HTML.
//!
//! The rendered pages are intentionally conservative on visual
//! polish — this is a friction gate, not a product surface. A future
//! UX story may style them per-route; story 3.4 scope is functional
//! correctness + unit-test coverage of the string composition.

use crate::{pow::Challenge, Mode};

/// Entry points used by the proxy request filter.
///
/// Each `render_*` function returns a full HTML document ready to
/// serve as a response body. Content type is always
/// `text/html; charset=utf-8`; the caller sets the header.
///
/// Every argument that is substituted into the page is passed
/// through HTML escaping so a route hostname containing `</script>`
/// cannot break out of the JS block, and a submit URL containing
/// `"` cannot escape the attribute context.
pub fn render_cookie_refresh_page(target_url: &str, operator_contact: Option<&str>) -> String {
    let target_esc = html_escape(target_url);
    let contact_line = render_contact_line(operator_contact);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="1; url={target_esc}">
<title>Checking your browser...</title>
<style>{CSS}</style>
</head>
<body>
<main class="card">
<h1>Checking your browser</h1>
<p class="muted">A quick redirect verifies your session.</p>
<p class="muted">If this page does not redirect after a moment, <a href="{target_esc}">click here</a>.</p>
{contact_line}
</main>
</body>
</html>
"#,
    )
}

/// Render the JavaScript proof-of-work challenge page. The
/// embedded JS runs SHA-256 over `hex_nonce || counter_decimal`
/// until it finds a counter with the right number of leading zero
/// bits, then POSTs the solution to `submit_url` with the nonce +
/// counter as application/x-www-form-urlencoded fields.
pub fn render_pow_page(
    challenge: &Challenge,
    submit_url: &str,
    operator_contact: Option<&str>,
) -> String {
    let submit_esc = html_escape(submit_url);
    let nonce_hex = challenge.nonce_hex();
    let nonce_esc = html_escape(&nonce_hex);
    let difficulty = challenge.difficulty;
    let expires_at = challenge.expires_at;
    let contact_line = render_contact_line(operator_contact);

    // Expected solve-time hint for the user. Matches the scale
    // table in `docs/architecture/bot-protection.md` § 3.2. Values
    // are rough medians; we round to "about X" phrasing so no user
    // holds us to the wall clock.
    let hint = match difficulty {
        14 => "less than a second",
        15 => "about a second",
        16 | 17 => "a few seconds",
        18 => "about a second on desktop, a couple of seconds on mobile",
        19 => "a few seconds",
        20..=21 => "up to ten seconds",
        _ => "up to thirty seconds",
    };

    // The embedded JS uses crypto.subtle.digest, available in every
    // evergreen browser (and in Node when packaged through wrap
    // layers). The worker runs in the main JS context — a Web
    // Worker would keep the UI thread responsive for high N but
    // adds ~4 KiB of bundle. v1.4.0 keeps it simple; a future UX
    // polish story can switch to a Worker if sub-second input
    // lag becomes a complaint.
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>One moment please...</title>
<style>{CSS}</style>
</head>
<body>
<main class="card">
<h1>Verifying your connection</h1>
<p class="muted">We are running a short cryptographic check to confirm this request comes from a real browser. It should take {hint}.</p>
<progress id="bar" value="0" max="1"></progress>
<p id="status" class="muted" aria-live="polite">Working...</p>
<noscript>
<p class="warn">JavaScript is required to complete this check. Please enable JavaScript in your browser and reload the page.</p>
</noscript>
{contact_line}
<form id="f" action="{submit_esc}" method="post" hidden>
<input type="hidden" name="nonce" value="{nonce_esc}">
<input type="hidden" name="counter" id="counter">
</form>
</main>
<script>
(function () {{
  var NONCE_HEX = "{nonce_esc}";
  var DIFFICULTY = {difficulty};
  var EXPIRES_AT = {expires_at};
  var status = document.getElementById("status");
  var bar = document.getElementById("bar");
  var form = document.getElementById("f");
  var counterField = document.getElementById("counter");

  // ~2^DIFFICULTY attempts expected. We cap the progress bar to
  // that budget but keep searching if the expected budget runs
  // out without a hit (happens ~1 in e times).
  var budget = Math.pow(2, DIFFICULTY);
  var attempts = 0;
  var counter = 0;
  var encoder = new TextEncoder();

  function bytesLeadingZeros(bytes, n) {{
    var fullBytes = Math.floor(n / 8);
    var remainder = n % 8;
    for (var i = 0; i < fullBytes; i++) {{
      if (bytes[i] !== 0) return false;
    }}
    if (remainder === 0) return true;
    if (bytes.length <= fullBytes) return false;
    var mask = 0xFF << (8 - remainder) & 0xFF;
    return (bytes[fullBytes] & mask) === 0;
  }}

  async function step() {{
    if (Math.floor(Date.now() / 1000) > EXPIRES_AT) {{
      status.textContent = "Challenge expired. Please reload the page to retry.";
      status.className = "warn";
      return;
    }}
    // Iterate in chunks so the UI thread yields between batches.
    var deadline = performance.now() + 40;
    while (performance.now() < deadline) {{
      var preimage = encoder.encode(NONCE_HEX + counter.toString());
      var digest = await crypto.subtle.digest("SHA-256", preimage);
      var bytes = new Uint8Array(digest);
      attempts++;
      if (bytesLeadingZeros(bytes, DIFFICULTY)) {{
        counterField.value = counter.toString();
        status.textContent = "Done. Submitting...";
        bar.value = 1;
        form.submit();
        return;
      }}
      counter++;
    }}
    bar.value = Math.min(1, attempts / budget);
    requestAnimationFrame(step);
  }}
  step();
}})();
</script>
</body>
</html>
"#,
    )
}

/// Render the image-captcha page. `image_url` points at the
/// one-shot URL that serves the PNG; `submit_url` is where the
/// user's answer is POSTed (typically the same URL as the
/// challenge page itself, distinguished by method). `nonce` is
/// the server-side stash key echoed back in a hidden form field
/// so the verifier can pull the expected text out of the stash.
/// Every string is escaped into its respective attribute /
/// element context.
pub fn render_captcha_page(
    image_url: &str,
    submit_url: &str,
    nonce: &str,
    operator_contact: Option<&str>,
) -> String {
    let image_esc = html_escape(image_url);
    let submit_esc = html_escape(submit_url);
    let nonce_esc = html_escape(nonce);
    let contact_line = render_contact_line(operator_contact);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Please prove you are human</title>
<style>{CSS}</style>
</head>
<body>
<main class="card">
<h1>Please prove you are human</h1>
<p class="muted">Type the characters shown in the image below. The match is case-insensitive.</p>
<img src="{image_esc}" alt="Captcha image (if you cannot read it, reload the page)" class="captcha">
<form action="{submit_esc}" method="post" autocomplete="off">
<input type="hidden" name="nonce" value="{nonce_esc}">
<label for="answer" class="muted">Answer</label>
<input id="answer" name="answer" type="text" spellcheck="false" autocapitalize="off" required autofocus>
<button type="submit">Submit</button>
</form>
{contact_line}
</main>
</body>
</html>
"#,
    )
}

/// Plain-text fallback for clients that did not advertise
/// `text/html` in their `Accept` header. Curl / wget / scripts get
/// a meaningful line instead of the full HTML dump. The body fits
/// well under an 8 KiB buffer so even a terminal-bound user can
/// skim it.
pub fn render_plaintext_fallback(mode: Mode, operator_contact: Option<&str>) -> String {
    let mode_name = mode.as_str();
    let intro = match mode {
        Mode::Cookie => {
            "This route is protected by a browser cookie check. Your HTTP client \
             must accept cookies and follow redirects to pass."
        }
        Mode::Javascript => {
            "This route is protected by a JavaScript proof-of-work challenge. \
             A browser with JavaScript enabled is required to pass."
        }
        Mode::Captcha => {
            "This route is protected by an image captcha. A human operator is \
             required to read the image and submit the answer."
        }
    };
    let contact = match operator_contact {
        Some(c) if !c.trim().is_empty() => format!("Operator contact: {}\n", c.trim()),
        _ => String::new(),
    };
    format!(
        "403 Forbidden\n\
         \n\
         Bot protection: {mode_name} mode.\n\
         {intro}\n\
         \n\
         If you believe this is a mistake, reload the page in a graphical browser.\n\
         {contact}",
    )
}

/// Render the small "contact the operator" line that lives at the
/// bottom of every HTML challenge page. Returns an empty string
/// when no contact is configured so the `<p>` is not emitted at
/// all.
fn render_contact_line(operator_contact: Option<&str>) -> String {
    match operator_contact {
        Some(c) if !c.trim().is_empty() => {
            format!(
                "<p class=\"muted small\">Think this is a mistake? Contact: {}</p>",
                html_escape(c.trim())
            )
        }
        _ => String::new(),
    }
}

/// HTML-escape a substituted string. Handles the five characters
/// that can escape out of an attribute or text context:
/// `& < > " '`. Written long-hand (rather than via `html_escape`
/// crate) so the crate adds no dep for ~10 lines of code and the
/// escape rules are locally auditable.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Inline CSS shared by the three HTML pages. Minimal, system-font
/// only (no web-font fetch), works at mobile widths, respects the
/// `prefers-color-scheme: dark` media query so a user on a dark-
/// themed browser does not get a flashbang white card.
const CSS: &str = "
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;
background:#f7f7f8;color:#1a1a1a}
.card{max-width:480px;margin:16px;padding:32px 24px;border-radius:12px;background:#fff;
box-shadow:0 2px 12px rgba(0,0,0,0.08);text-align:center}
h1{margin:0 0 12px;font-size:20px;font-weight:600}
.muted{color:#6a6a6a;font-size:14px;line-height:1.5}
.small{font-size:12px;margin-top:16px}
.warn{color:#b32;font-size:14px;margin-top:12px}
progress{width:100%;height:8px;margin:20px 0 8px}
img.captcha{display:block;margin:20px auto;max-width:100%;border-radius:6px;
border:1px solid #ddd}
input[type=text]{width:100%;padding:10px 12px;font-size:16px;border:1px solid #ccc;
border-radius:6px;box-sizing:border-box;margin:8px 0}
label{display:block;text-align:left;margin-top:16px}
button{margin-top:12px;padding:10px 20px;font-size:15px;background:#0b57d0;color:#fff;
border:none;border-radius:6px;cursor:pointer}
button:hover{background:#094cb5}
a{color:#0b57d0}
@media(prefers-color-scheme:dark){
body{background:#1e1e1f;color:#eaeaea}
.card{background:#2a2a2b;box-shadow:0 2px 12px rgba(0,0,0,0.3)}
.muted{color:#aaa}
input[type=text]{background:#1e1e1f;color:#eaeaea;border-color:#444}
a{color:#8ab4f8}
}
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_covers_the_five_danger_chars() {
        assert_eq!(
            html_escape("<script>alert(\"x\")</script>&'"),
            "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&amp;&#x27;"
        );
    }

    #[test]
    fn html_escape_preserves_safe_chars() {
        let s = "normal text with spaces 123 é ñ";
        assert_eq!(html_escape(s), s);
    }

    #[test]
    fn cookie_refresh_page_contains_escaped_target() {
        let page = render_cookie_refresh_page("/original?a=1&b=2", None);
        // Query separator `&` must be escaped in the `meta refresh`
        // URL attribute so the browser parses the URL correctly.
        assert!(
            page.contains("url=/original?a=1&amp;b=2"),
            "meta refresh target not escaped: {page}"
        );
        // And in the `<a href>` fallback.
        assert!(page.contains("href=\"/original?a=1&amp;b=2\""));
        // Must carry the meta-refresh tag (browsers without JS
        // still bounce through).
        assert!(page.contains("http-equiv=\"refresh\""));
    }

    #[test]
    fn cookie_refresh_page_optional_contact_line() {
        let with = render_cookie_refresh_page("/", Some("ops@example.com"));
        assert!(with.contains("ops@example.com"));
        let without = render_cookie_refresh_page("/", None);
        assert!(!without.contains("Contact:"));
        // Empty string contact is treated the same as None.
        let empty = render_cookie_refresh_page("/", Some("   "));
        assert!(!empty.contains("Contact:"));
    }

    #[test]
    fn pow_page_embeds_challenge_fields() {
        let c = Challenge::new(18, 1_000, 300).unwrap();
        let page = render_pow_page(&c, "/lorica/bot/solve", None);
        assert!(page.contains("DIFFICULTY = 18"));
        assert!(page.contains("EXPIRES_AT = 1300"));
        assert!(page.contains(&c.nonce_hex()));
        assert!(page.contains("/lorica/bot/solve"));
        // noscript block MUST be present so a browser without JS
        // gets a useful message instead of a silent blank page.
        assert!(page.contains("<noscript>"));
        // Must use crypto.subtle.digest (no polyfill, no external
        // script).
        assert!(page.contains("crypto.subtle.digest"));
    }

    #[test]
    fn pow_page_escapes_submit_url_in_form_action() {
        let c = Challenge::new(14, 0, 300).unwrap();
        let page = render_pow_page(&c, "/solve?x=\"><script>alert(1)</script>", None);
        // The naive raw string would break out of the attribute;
        // the escape must turn `"` into `&quot;` and `<` into `&lt;`.
        assert!(!page.contains("<script>alert(1)</script>"));
        assert!(page.contains("&quot;&gt;&lt;script&gt;"));
    }

    #[test]
    fn captcha_page_wires_image_and_submit_urls() {
        let page = render_captcha_page("/captcha/abc", "/solve", "nonce123", None);
        assert!(page.contains("src=\"/captcha/abc\""));
        assert!(page.contains("action=\"/solve\""));
        assert!(page.contains("name=\"answer\""));
        assert!(page.contains("name=\"nonce\""));
        assert!(page.contains("value=\"nonce123\""));
        assert!(page.contains("autofocus"));
    }

    #[test]
    fn plaintext_fallback_mentions_mode() {
        let p = render_plaintext_fallback(Mode::Javascript, None);
        assert!(p.starts_with("403 Forbidden"));
        assert!(p.contains("javascript"));
        assert!(p.contains("JavaScript"));
    }

    #[test]
    fn plaintext_fallback_includes_contact_when_set() {
        let p = render_plaintext_fallback(Mode::Captcha, Some("abuse@example.com"));
        assert!(p.contains("Operator contact: abuse@example.com"));
        let empty = render_plaintext_fallback(Mode::Captcha, Some("  "));
        assert!(!empty.contains("Operator contact"));
    }

    #[test]
    fn pow_page_hint_scales_with_difficulty() {
        // Spot-check three difficulty points to make sure the
        // hint string matches the scale table in the design doc.
        // Regression guard: if someone bumps DEFAULT_DIFFICULTY
        // without updating the hint, this catches it.
        let c14 = render_pow_page(&Challenge::new(14, 0, 300).unwrap(), "/s", None);
        let c18 = render_pow_page(&Challenge::new(18, 0, 300).unwrap(), "/s", None);
        let c22 = render_pow_page(&Challenge::new(22, 0, 300).unwrap(), "/s", None);
        assert!(c14.contains("less than a second"));
        assert!(c18.contains("about a second on desktop"));
        assert!(c22.contains("thirty seconds"));
    }

    #[test]
    fn all_three_html_pages_declare_utf8() {
        let c = Challenge::new(14, 0, 300).unwrap();
        let cookie = render_cookie_refresh_page("/", None);
        let pow = render_pow_page(&c, "/", None);
        let captcha = render_captcha_page("/c", "/s", "n", None);
        for p in [cookie, pow, captcha] {
            assert!(p.contains("charset=\"utf-8\""), "page missing charset: {p}");
        }
    }
}
