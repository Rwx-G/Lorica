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

//! Configuration intake (Story 11.1 AC #1): where this server's
//! automation endpoint and bearer token come from, and where they are
//! refused.
//!
//! # Never argv
//!
//! AC #1 names the reason and it is not style: on Linux every local
//! user reads `/proc/<pid>/cmdline`, so a token passed as an argument
//! is a token published to the machine. An MCP client launches this
//! process, and the natural thing for a client author to write is an
//! `args` array, so the refusal has to be loud and has to name the two
//! environment variables instead. A process started with any argument
//! at all therefore refuses to start, rather than ignoring the argument
//! and leaving whoever wrote it believing it took effect.
//!
//! # Environment or file, and which wins
//!
//! [`ENDPOINT_ENV`] and [`TOKEN_ENV`] are the primary intake. A client
//! that cannot set an environment variable per server names a TOML file
//! in [`CONFIG_ENV`] instead. The environment wins where both speak,
//! because it is the one an operator can change without editing a file
//! a client may rewrite.
//!
//! # Nothing here ever prints the token
//!
//! [`Secret`] has a [`fmt::Debug`] that redacts and no [`fmt::Display`]
//! at all, so a token reaches a log only if somebody calls
//! [`Secret::reveal`] and writes it out on purpose. The malformed-file
//! error is the other half of that: a TOML parse failure carries the
//! offending line, and the offending line of this file is as likely as
//! not the one holding the token, so the parse detail is dropped and
//! the path alone is reported.

use core::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The automation endpoint, as `https://host:port`.
pub const ENDPOINT_ENV: &str = "LORICA_MCP_ENDPOINT";

/// The automation bearer token.
pub const TOKEN_ENV: &str = "LORICA_MCP_TOKEN";

/// Path to a TOML file carrying `endpoint` and `token`.
pub const CONFIG_ENV: &str = "LORICA_MCP_CONFIG";

/// The most bytes a bearer token may weigh.
///
/// A Lorica automation token is a public id and a secret half, tens of
/// bytes. The ceiling is here so a file or an environment variable that
/// is not a token at all is refused as configuration rather than sent
/// to the plane as an `Authorization` header.
const MAX_TOKEN_BYTES: usize = 4096;

/// A value that must not reach a log, a panic message or an error.
///
/// The redacting [`fmt::Debug`] is the whole type: it is what makes
/// `tracing::debug!(?config)` safe, and what makes writing the token
/// out require somebody to type [`Secret::reveal`] at the call site
/// where a reviewer sees it.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// The value itself, for the one place that puts it on the wire.
    pub fn reveal(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// What this server needs before it can ask the plane anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    /// The automation listener's origin, `https://host:port`, with no
    /// trailing slash and no path.
    pub endpoint: String,
    /// The bearer token every request to that listener carries.
    pub token: Secret,
}

/// Why configuration was refused.
///
/// Every variant's message is written for the operator who will read it
/// on stderr and has to fix it. None of them echoes the token, and the
/// file variants name the path without quoting anything from inside the
/// file.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// The process was started with command-line arguments.
    ArgumentsRefused,
    /// Neither the environment nor the file named an endpoint.
    MissingEndpoint,
    /// Neither the environment nor the file named a token.
    MissingToken,
    /// The endpoint is not an `https://` origin.
    EndpointNotHttps,
    /// The endpoint carries a userinfo component, which would mean a
    /// second credential in a place nothing here redacts.
    EndpointCarriesCredentials,
    /// The endpoint has a path, query or fragment: this server appends
    /// its own paths and would build nonsense from a prefix.
    EndpointIsNotAnOrigin,
    /// The token is empty, or carries a byte that cannot travel in an
    /// HTTP header.
    TokenUnusable,
    /// The file named by [`CONFIG_ENV`] could not be read.
    FileUnreadable {
        /// The path that was named.
        path: PathBuf,
        /// The operating system's reason, which names no file content.
        detail: String,
    },
    /// The file named by [`CONFIG_ENV`] is not the TOML this expects.
    ///
    /// Carries no parse detail on purpose: a TOML error quotes the line
    /// it failed on, and in this file that line may be the token.
    FileMalformed {
        /// The path that was named.
        path: PathBuf,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::ArgumentsRefused => write!(
                f,
                "lorica-mcp takes no command-line arguments. The endpoint and the token are \
                 read from {ENDPOINT_ENV} and {TOKEN_ENV}, or from the TOML file named by \
                 {CONFIG_ENV}. An argument would put the token in the process table, where \
                 every local user reads it."
            ),
            ConfigError::MissingEndpoint => write!(
                f,
                "no automation endpoint: set {ENDPOINT_ENV} to the listener's origin \
                 (https://host:port), or name a TOML file in {CONFIG_ENV} carrying an \
                 `endpoint` key."
            ),
            ConfigError::MissingToken => write!(
                f,
                "no automation token: set {TOKEN_ENV}, or name a TOML file in {CONFIG_ENV} \
                 carrying a `token` key."
            ),
            ConfigError::EndpointNotHttps => write!(
                f,
                "the automation endpoint must be https://. The bearer token travels on every \
                 request, and over plaintext it travels to whoever is listening."
            ),
            ConfigError::EndpointCarriesCredentials => write!(
                f,
                "the automation endpoint must carry no user information before the host. \
                 Lorica authenticates with the bearer token from {TOKEN_ENV} and nothing else."
            ),
            ConfigError::EndpointIsNotAnOrigin => write!(
                f,
                "the automation endpoint is an origin (https://host:port) and nothing more. \
                 This server appends the paths it reads; a path, query or fragment here would \
                 be prepended to every one of them."
            ),
            ConfigError::TokenUnusable => write!(
                f,
                "the automation token is empty or carries a byte an HTTP header cannot. \
                 Check {TOKEN_ENV} for a trailing newline or a shell quoting mistake."
            ),
            ConfigError::FileUnreadable { path, detail } => write!(
                f,
                "cannot read the configuration file named by {CONFIG_ENV} ({}): {detail}",
                path.display()
            ),
            ConfigError::FileMalformed { path } => write!(
                f,
                "the configuration file named by {CONFIG_ENV} ({}) is not valid TOML with \
                 optional string keys `endpoint` and `token`. The parse error is withheld \
                 because it would quote the line it failed on, and that line may be the token.",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

/// The two keys the TOML file may carry, both optional so the file can
/// name the endpoint while the environment carries the token.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    endpoint: Option<String>,
    token: Option<String>,
}

impl ServerConfig {
    /// Assemble a configuration from already-gathered inputs.
    ///
    /// Pure: `arguments` is what followed the program name, `env`
    /// answers a variable, and `file` is the TOML text already read (or
    /// `None` when [`CONFIG_ENV`] named nothing). Splitting the I/O out
    /// is what lets the refusals be tested without a process or a
    /// filesystem, which is the half of AC #1 that has to stay true.
    ///
    /// # Errors
    ///
    /// Any [`ConfigError`]; see that type for what each means.
    pub fn assemble(
        arguments: &[String],
        env: impl Fn(&str) -> Option<String>,
        file: Option<(&Path, &str)>,
    ) -> Result<ServerConfig, ConfigError> {
        if !arguments.is_empty() {
            return Err(ConfigError::ArgumentsRefused);
        }

        let from_file = match file {
            Some((path, text)) => {
                toml::from_str::<ConfigFile>(text).map_err(|_| ConfigError::FileMalformed {
                    path: path.to_path_buf(),
                })?
            }
            None => ConfigFile::default(),
        };

        // A variable set to nothing reads as unset. An MCP client that
        // always writes both keys into its `env` object would otherwise
        // shadow the file with a blank string, and the operator would
        // meet "must be https://" about a value they never typed.
        let spoken = |name: &str| env(name).filter(|value| !value.trim().is_empty());
        let endpoint = spoken(ENDPOINT_ENV)
            .or(from_file.endpoint)
            .ok_or(ConfigError::MissingEndpoint)?;
        let token = spoken(TOKEN_ENV)
            .or(from_file.token)
            .ok_or(ConfigError::MissingToken)?;

        Ok(ServerConfig {
            endpoint: checked_endpoint(endpoint.trim())?,
            token: Secret(checked_token(token.trim())?),
        })
    }

    /// Assemble from this process's own arguments, environment and, if
    /// [`CONFIG_ENV`] names one, configuration file.
    ///
    /// # Errors
    ///
    /// Any [`ConfigError`], including [`ConfigError::FileUnreadable`],
    /// which only this entry point can produce.
    pub fn from_process() -> Result<ServerConfig, ConfigError> {
        let arguments: Vec<String> = std::env::args().skip(1).collect();
        // Read before `assemble` so the file's own failure is reported
        // as itself; an unreadable path must not surface as "no
        // endpoint", which sends an operator to the wrong variable.
        let named = std::env::var(CONFIG_ENV).ok().map(PathBuf::from);
        let contents = match &named {
            Some(path) => Some(std::fs::read_to_string(path).map_err(|reason| {
                ConfigError::FileUnreadable {
                    path: path.clone(),
                    detail: reason.to_string(),
                }
            })?),
            None => None,
        };
        let file = named.as_deref().zip(contents.as_deref());

        ServerConfig::assemble(&arguments, |name| std::env::var(name).ok(), file)
    }
}

/// The endpoint if it is an origin this server may append paths to.
fn checked_endpoint(endpoint: &str) -> Result<String, ConfigError> {
    let authority = endpoint
        .strip_prefix("https://")
        .ok_or(ConfigError::EndpointNotHttps)?;
    if authority.contains('@') {
        return Err(ConfigError::EndpointCarriesCredentials);
    }
    if authority.is_empty() || authority.contains(['/', '?', '#']) {
        return Err(ConfigError::EndpointIsNotAnOrigin);
    }
    Ok(endpoint.to_string())
}

/// The token if it can travel in an `Authorization` header.
///
/// Visible ASCII only, which is narrower than the header grammar allows
/// and wider than any token this plane mints. The value is never named
/// in the refusal: a message quoting what it rejected is a message that
/// writes the token to stderr for every malformed one.
fn checked_token(token: &str) -> Result<String, ConfigError> {
    if token.is_empty()
        || token.len() > MAX_TOKEN_BYTES
        || !token.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(ConfigError::TokenUnusable);
    }
    Ok(token.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An environment answering exactly `pairs` and nothing else.
    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_string())
        }
    }

    const ENDPOINT: &str = "https://lorica.internal.example.org:8443";
    const TOKEN: &str = "lam_0123456789abcdef.s3cr3t";

    #[test]
    fn an_argument_refuses_the_start_and_says_where_the_token_goes_instead() {
        // The failure this exists for: a client author writes an `args`
        // array, the token lands in /proc/<pid>/cmdline, and every
        // local user reads it. Ignoring the argument would be worse
        // than refusing, because whoever wrote it would believe it took
        // effect.
        let refused = ServerConfig::assemble(
            &["--token".to_string(), TOKEN.to_string()],
            env_of(&[(ENDPOINT_ENV, ENDPOINT), (TOKEN_ENV, TOKEN)]),
            None,
        )
        .expect_err("an argument is refused even when the environment is complete");
        assert_eq!(refused, ConfigError::ArgumentsRefused);
        let message = refused.to_string();
        assert!(message.contains(TOKEN_ENV), "{message}");
        assert!(!message.contains(TOKEN), "{message}");
    }

    #[test]
    fn the_environment_carries_the_endpoint_and_the_token() {
        let config = ServerConfig::assemble(
            &[],
            env_of(&[(ENDPOINT_ENV, ENDPOINT), (TOKEN_ENV, TOKEN)]),
            None,
        )
        .expect("a complete environment is a configuration");
        assert_eq!(config.endpoint, ENDPOINT);
        assert_eq!(config.token.reveal(), TOKEN);
    }

    #[test]
    fn a_file_carries_them_when_the_environment_does_not_and_loses_when_it_does() {
        let path = Path::new("/etc/lorica/mcp.toml");
        let text = format!("endpoint = \"{ENDPOINT}\"\ntoken = \"{TOKEN}\"\n");

        let from_file = ServerConfig::assemble(&[], env_of(&[]), Some((path, &text)))
            .expect("the file alone is a configuration");
        assert_eq!(from_file.endpoint, ENDPOINT);
        assert_eq!(from_file.token.reveal(), TOKEN);

        // The environment wins: it is the half an operator changes
        // without editing a file the client may rewrite.
        let overridden = ServerConfig::assemble(
            &[],
            env_of(&[(TOKEN_ENV, "lam_from.environment")]),
            Some((path, &text)),
        )
        .expect("the file supplies what the environment does not");
        assert_eq!(overridden.endpoint, ENDPOINT);
        assert_eq!(overridden.token.reveal(), "lam_from.environment");

        // A variable set to nothing reads as unset. A client that
        // always writes both keys into its `env` object would otherwise
        // shadow the file with a blank string.
        let blank = ServerConfig::assemble(
            &[],
            env_of(&[(ENDPOINT_ENV, ""), (TOKEN_ENV, "   ")]),
            Some((path, &text)),
        )
        .expect("a blank variable falls through to the file");
        assert_eq!(blank.endpoint, ENDPOINT);
        assert_eq!(blank.token.reveal(), TOKEN);
    }

    #[test]
    fn a_malformed_file_names_the_path_and_quotes_nothing_from_inside_it() {
        // A TOML parse error carries the offending line, and in this
        // file that line is as likely as not the token.
        let path = Path::new("/etc/lorica/mcp.toml");
        let refused = ServerConfig::assemble(
            &[],
            env_of(&[]),
            Some((path, &format!("token = {TOKEN}\n"))),
        )
        .expect_err("an unquoted value is not TOML");
        assert_eq!(
            refused,
            ConfigError::FileMalformed {
                path: path.to_path_buf()
            }
        );
        let message = refused.to_string();
        assert!(message.contains("mcp.toml"), "{message}");
        assert!(!message.contains(TOKEN), "{message}");

        // A key nobody declared is a mistake worth reporting, not a
        // value to ignore: `tokne = ` would otherwise read as "no
        // token" and send the operator to the wrong variable.
        let refused = ServerConfig::assemble(
            &[],
            env_of(&[]),
            Some((path, "endpoint = \"https://h\"\ntokne = \"x\"\n")),
        )
        .expect_err("an undeclared key is refused");
        assert!(matches!(refused, ConfigError::FileMalformed { .. }));
    }

    #[test]
    fn a_missing_half_names_the_half_that_is_missing() {
        assert_eq!(
            ServerConfig::assemble(&[], env_of(&[(TOKEN_ENV, TOKEN)]), None)
                .expect_err("no endpoint"),
            ConfigError::MissingEndpoint
        );
        assert_eq!(
            ServerConfig::assemble(&[], env_of(&[(ENDPOINT_ENV, ENDPOINT)]), None)
                .expect_err("no token"),
            ConfigError::MissingToken
        );
    }

    #[test]
    fn the_endpoint_is_an_https_origin_and_nothing_else() {
        let refuses = |endpoint: &str| {
            ServerConfig::assemble(
                &[],
                env_of(&[(ENDPOINT_ENV, endpoint), (TOKEN_ENV, TOKEN)]),
                None,
            )
            .expect_err(endpoint)
        };

        // Plaintext would put the bearer token on the wire in clear on
        // every single request.
        assert_eq!(
            refuses("http://lorica.internal.example.org:8443"),
            ConfigError::EndpointNotHttps
        );
        assert_eq!(
            refuses("lorica.internal.example.org"),
            ConfigError::EndpointNotHttps
        );
        // Userinfo is a second credential in a field nothing here
        // redacts.
        assert_eq!(
            refuses("https://user01:pass@lorica.internal.example.org"),
            ConfigError::EndpointCarriesCredentials
        );
        // A prefix would be prepended to every path this server builds.
        for not_an_origin in [
            "https://lorica.internal.example.org/automation/v1",
            "https://lorica.internal.example.org/",
            "https://lorica.internal.example.org?x=1",
            "https://lorica.internal.example.org#f",
            "https://",
        ] {
            assert_eq!(
                refuses(not_an_origin),
                ConfigError::EndpointIsNotAnOrigin,
                "{not_an_origin}"
            );
        }
    }

    #[test]
    fn a_token_that_cannot_travel_in_a_header_is_refused_without_being_quoted() {
        for unusable in ["has space", "has\nnewline", "has\ttab"] {
            let refused = ServerConfig::assemble(
                &[],
                env_of(&[(ENDPOINT_ENV, ENDPOINT), (TOKEN_ENV, unusable)]),
                None,
            )
            .expect_err("unusable token");
            assert_eq!(refused, ConfigError::TokenUnusable, "{unusable:?}");
            assert!(!refused.to_string().contains(unusable), "{unusable:?}");
        }

        // A variable set to nothing is unset rather than unusable, and
        // says so: an operator who set it blank needs to be sent to the
        // variable, not to the shape of a value they never typed.
        for blank in ["", "   "] {
            assert_eq!(
                ServerConfig::assemble(
                    &[],
                    env_of(&[(ENDPOINT_ENV, ENDPOINT), (TOKEN_ENV, blank)]),
                    None,
                )
                .expect_err("a blank token is no token"),
                ConfigError::MissingToken,
                "{blank:?}"
            );
        }

        // A surrounding newline is the commonest way a token arrives
        // from a shell and is not a mistake worth refusing.
        let trimmed = ServerConfig::assemble(
            &[],
            env_of(&[
                (ENDPOINT_ENV, ENDPOINT),
                (TOKEN_ENV, &format!("  {TOKEN}\n")),
            ]),
            None,
        )
        .expect("a trailing newline is trimmed, not refused");
        assert_eq!(trimmed.token.reveal(), TOKEN);
    }

    #[test]
    fn the_token_is_redacted_in_every_debug_rendering() {
        // `tracing::debug!(?config)` must not be the thing that
        // publishes the credential.
        let config = ServerConfig::assemble(
            &[],
            env_of(&[(ENDPOINT_ENV, ENDPOINT), (TOKEN_ENV, TOKEN)]),
            None,
        )
        .expect("a complete environment is a configuration");
        let rendered = format!("{config:?}");
        assert!(!rendered.contains(TOKEN), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
        assert!(rendered.contains(ENDPOINT), "the endpoint is not a secret");
    }
}
