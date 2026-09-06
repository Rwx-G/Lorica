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

/// The management password from its documented sources, in order:
/// `--password-file`, `--password-stdin`, `LORICA_ADMIN_PASSWORD`,
/// then `--password` (accepted with a warning: argv is readable
/// through `/proc`, lands in shell history and is logged verbatim by
/// CI and configuration-management `command` modules).
pub(crate) fn read_admin_password(
    literal: Option<String>,
    file: Option<&Path>,
    from_stdin: bool,
) -> Result<String, String> {
    if let Some(path) = file {
        return std::fs::read_to_string(path)
            .map(|s| s.trim_end_matches(['\r', '\n']).to_string())
            .map_err(|e| format!("cannot read the password file {}: {e}", path.display()));
    }
    if from_stdin {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .map_err(|e| format!("cannot read the password from standard input: {e}"))?;
        return Ok(buffer.trim_end_matches(['\r', '\n']).to_string());
    }
    if let Ok(from_env) = std::env::var("LORICA_ADMIN_PASSWORD") {
        if !from_env.is_empty() {
            return Ok(from_env);
        }
    }
    if let Some(literal) = literal {
        eprintln!(
            "warning: --password on the command line is visible to every local process and \
             lands in shell history; prefer --password-file, --password-stdin or \
             LORICA_ADMIN_PASSWORD"
        );
        return Ok(literal);
    }
    Err("no password: pass --password-file <path>, --password-stdin, set LORICA_ADMIN_PASSWORD, \
         or (discouraged) --password"
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_sources_follow_the_documented_precedence() {
        let file = std::env::temp_dir().join(format!("lorica-pw-{}", std::process::id()));
        std::fs::write(&file, "from-file\n").expect("write");
        assert_eq!(
            read_admin_password(Some("literal".into()), Some(&file), false).expect("file"),
            "from-file"
        );
        assert_eq!(
            read_admin_password(Some("literal".into()), None, false).expect("literal"),
            "literal"
        );
        assert!(read_admin_password(None, None, false).is_err()
            || std::env::var("LORICA_ADMIN_PASSWORD").is_ok());
        assert!(read_admin_password(None, Some(Path::new("/nonexistent/pw")), false).is_err());
        let _ = std::fs::remove_file(&file);
    }
}
