// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The loopback management-API client every CLI subcommand shares
//! (`unban`, the `cluster` family): one place for the trust decision,
//! the login contract and the password sources.

use std::io::Read;
use std::path::Path;

/// Exit with a message on stderr (the CLI's failure contract).
pub(crate) fn fail(message: impl std::fmt::Display) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

/// A client for the loopback management API. The management API is
/// served over TLS on localhost (Story 8.8 AC #1), by default with an
/// auto-generated self-signed certificate. `danger_accept_invalid_certs`
/// is intentional: the target is always `127.0.0.1`, so there is no
/// MITM surface to defend against, and the self-signed leaf has no
/// chain to validate.
pub(crate) fn management_client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .danger_accept_invalid_certs(true)
        .build()
        .expect("HTTP client")
}

/// Log in on the management API; exits with a diagnostic on failure.
pub(crate) async fn management_login(
    client: &reqwest::Client,
    port: u16,
    user: &str,
    password: &str,
) {
    let login_url = format!("https://127.0.0.1:{port}/api/v1/auth/login");
    match client
        .post(&login_url)
        .json(&serde_json::json!({ "username": user, "password": password }))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => {}
        Ok(r) => fail(format!("Login failed ({}). Check credentials.", r.status())),
        Err(e) => fail(format!(
            "Cannot connect to management API on port {port}: {e}. \
             Hint: is lorica running and is --management-port correct?"
        )),
    }
}

/// The `data` envelope of a management API answer, or exit with the
/// body.
pub(crate) async fn management_data(response: reqwest::Response, what: &str) -> serde_json::Value {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        fail(format!("{what} failed ({status}): {body}"));
    }
    serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("data").cloned())
        .unwrap_or_else(|| fail(format!("{what}: unexpected answer: {body}")))
}

/// The environment variable the management password is read from
/// when no explicit source is given.
pub(crate) const ADMIN_PASSWORD_ENV: &str = "LORICA_ADMIN_PASSWORD";

/// The management password from its documented sources. Explicit
/// arguments win over the ambient environment, in this order:
/// `--password-file`, `--password-stdin`, `--password` (accepted with
/// a warning: argv is readable through `/proc`, lands in shell history
/// and is logged verbatim by CI and configuration-management `command`
/// modules), then `LORICA_ADMIN_PASSWORD`. A trailing newline is
/// stripped from every source (`echo` and heredocs add one).
pub(crate) fn read_admin_password(
    literal: Option<String>,
    file: Option<&Path>,
    from_stdin: bool,
) -> Result<String, String> {
    read_admin_password_with_env(literal, file, from_stdin, std::env::var(ADMIN_PASSWORD_ENV).ok())
}

fn read_admin_password_with_env(
    literal: Option<String>,
    file: Option<&Path>,
    from_stdin: bool,
    from_env: Option<String>,
) -> Result<String, String> {
    let trimmed = |s: String| s.trim_end_matches(['\r', '\n']).to_string();
    if let Some(path) = file {
        return std::fs::read_to_string(path)
            .map(trimmed)
            .map_err(|e| format!("cannot read the password file {}: {e}", path.display()));
    }
    if from_stdin {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .map_err(|e| format!("cannot read the password from standard input: {e}"))?;
        return Ok(trimmed(buffer));
    }
    if let Some(literal) = literal {
        eprintln!(
            "warning: --password on the command line is visible to every local process and \
             lands in shell history; prefer --password-file, --password-stdin or \
             {ADMIN_PASSWORD_ENV}"
        );
        return Ok(literal);
    }
    if let Some(from_env) = from_env.map(trimmed).filter(|s| !s.is_empty()) {
        return Ok(from_env);
    }
    Err(format!(
        "no password: pass --password-file <path>, --password-stdin, set {ADMIN_PASSWORD_ENV}, \
         or (discouraged) --password"
    ))
}

/// The password for a command whose credentials are optional
/// (`cluster leave`, `cluster status`): `None` when no `--user` is
/// given AND no explicit password source was passed; a password
/// source without `--user` is a mistake worth naming rather than
/// silently ignoring (the command would then run credential-less).
pub(crate) fn optional_admin_password(
    user: Option<&str>,
    literal: Option<String>,
    file: Option<&Path>,
    from_stdin: bool,
) -> Option<String> {
    if user.is_none() {
        if literal.is_some() || file.is_some() || from_stdin {
            fail("a password source was given without --user; pass --user <name> as well");
        }
        return None;
    }
    Some(read_admin_password(literal, file, from_stdin).unwrap_or_else(|e| fail(e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_sources_follow_the_documented_precedence() {
        let file = std::env::temp_dir().join(format!("lorica-pw-{}", std::process::id()));
        std::fs::write(&file, "from-file\n").expect("write");
        let env = Some("from-env\n".to_string());
        // File beats everything.
        assert_eq!(
            read_admin_password_with_env(Some("literal".into()), Some(&file), false, env.clone())
                .expect("file"),
            "from-file"
        );
        // An explicit --password beats the ambient variable.
        assert_eq!(
            read_admin_password_with_env(Some("literal".into()), None, false, env.clone())
                .expect("literal"),
            "literal"
        );
        // The variable is the fallback, trimmed.
        assert_eq!(
            read_admin_password_with_env(None, None, false, env).expect("env"),
            "from-env"
        );
        // An empty variable is no source.
        assert!(read_admin_password_with_env(None, None, false, Some(String::new())).is_err());
        assert!(read_admin_password_with_env(None, None, false, None).is_err());
        assert!(read_admin_password_with_env(
            None,
            Some(Path::new("/nonexistent/pw")),
            false,
            None
        )
        .is_err());
        let _ = std::fs::remove_file(&file);
    }
}
