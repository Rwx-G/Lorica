//! The typed backend health check (Story 12.1, D-2; Story 12.7).
//!
//! Until 1.11.0 a backend's active check was described by one column,
//! `health_check_path`: a path meant an HTTP GET, no path a TCP connect.
//! [`HealthCheck`] names the kind instead, so a kind that is neither
//! (a send/expect exchange, a UDP probe) is a variant here rather than a
//! new column. `health_check_path` stays, written beside the typed
//! definition, because a 1.10.6 binary opening a 1.11.0 database after a
//! hot-upgrade rollback reads and writes that column only.
//! [`HealthCheck::reconcile`] is the one place the two are made to agree.
//!
//! Story 12.7 adds the two kinds that speak a protocol over plaintext
//! TCP: a named template from the release's catalogue
//! (`lorica_automation_policy::TCP_CHECK_TEMPLATES`), and a custom
//! exchange of operator-chosen bytes. Their limits are checked when a
//! check is written ([`Backend::validate_health_check`]), never when one
//! is decoded, so a later release that raises a limit does not make this
//! one's decode of its rows fail.

use std::borrow::Cow;
use std::time::Duration;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use lorica_automation_policy::health_templates::{tcp_check_template, TCP_CHECK_TEMPLATES};
pub use lorica_automation_policy::health_templates::{CheckTemplate, MatchAnchor};

use super::backend::Backend;

/// The most a custom `send` may carry, decoded. Every protocol greeting
/// surveyed fits in a few dozen bytes: a payload is a probe, not a
/// request body.
pub const SEND_MAX_BYTES: usize = 1024;

/// The most alternatives a custom `expect` may list. Alternatives exist
/// for "S or N" style answers, not for a grammar.
pub const EXPECT_MAX_ALTERNATIVES: usize = 8;

/// The most one expected alternative may carry, decoded. It bounds the
/// matching cost of a probe: every byte read is compared at most this
/// many times per alternative.
pub const EXPECT_MAX_BYTES: usize = 256;

/// The most one probe ever reads from a backend, whatever its check
/// says. Not configurable: a backend cannot make a probe buffer more.
pub const PROBE_READ_MAX_BYTES: usize = 4096;

/// The shortest probe timeout a check may set, in milliseconds.
pub const PROBE_TIMEOUT_MS_MIN: u32 = 100;

/// The longest probe timeout a check may set, in milliseconds: one
/// probe stays within two cycles at the 5 s probe interval floor.
pub const PROBE_TIMEOUT_MS_MAX: u32 = 10_000;

/// The probe timeout of a check that sets none, in milliseconds: the
/// TCP connect timeout every probe had before 1.11.0.
pub const PROBE_TIMEOUT_MS_DEFAULT: u32 = 5_000;

/// The serde default of `timeout_ms`.
pub fn default_probe_timeout_ms() -> u32 {
    PROBE_TIMEOUT_MS_DEFAULT
}

/// How the health loop actively probes a backend.
///
/// Whether it probes at all is `Backend::health_check_enabled`, and how
/// often is `Backend::health_check_interval_s`; this type only says
/// what one probe is.
///
/// Every kind refuses a field it does not have, the field-less ones
/// included: decoding goes through [`HealthCheckWire`], because serde
/// lets an internally tagged unit variant ignore extra keys whatever
/// `deny_unknown_fields` says.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HealthCheck {
    /// An HTTP GET of `path` on the backend; a 2xx or 3xx answer is
    /// healthy. HTTP routes only: a stream never speaks HTTP to its
    /// backends.
    Http {
        /// The request path, e.g. `/healthz`, query string included.
        path: String,
    },
    /// A TCP connection that completes is healthy. The default, and
    /// what every backend without a path was probed by before 1.11.0.
    #[default]
    TcpConnect,
    /// A template of the release's catalogue, referenced by name: the
    /// probe sends the template's bytes and expects one of its answers.
    /// Plaintext TCP only.
    TcpTemplate {
        /// The template, by name.
        template: TcpCheckTemplateName,
        /// The whole probe's deadline (connect, send, read), in
        /// milliseconds.
        timeout_ms: u32,
    },
    /// Operator-chosen bytes to send, if any, and the answers that make
    /// the probe healthy, any one of them. Plaintext TCP only. Written
    /// from the management plane only (PRD D9): see
    /// [`HealthCheck::carries_raw_payload`].
    TcpSendExpect {
        /// What the probe sends once connected; absent sends nothing.
        #[serde(skip_serializing_if = "Option::is_none")]
        send: Option<Payload>,
        /// The accepted answers, any one of them.
        expect: Vec<Expectation>,
        /// The whole probe's deadline (connect, send, read), in
        /// milliseconds.
        timeout_ms: u32,
    },
}

/// The decode shape of [`HealthCheck`]: the same tags and fields, with
/// every kind a struct variant so `deny_unknown_fields` reaches it.
/// `{"kind":"tcp_connect","path":"/x"}` is a definition this release
/// cannot honour (a 1.10.6 rollback could not either), not a TCP connect.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum HealthCheckWire {
    Http {
        path: String,
    },
    TcpConnect {},
    TcpTemplate {
        template: TcpCheckTemplateName,
        #[serde(default = "default_probe_timeout_ms")]
        timeout_ms: u32,
    },
    TcpSendExpect {
        #[serde(default)]
        send: Option<Payload>,
        expect: Vec<Expectation>,
        #[serde(default = "default_probe_timeout_ms")]
        timeout_ms: u32,
    },
}

impl<'de> Deserialize<'de> for HealthCheck {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match HealthCheckWire::deserialize(deserializer)? {
            HealthCheckWire::Http { path } => Self::Http { path },
            HealthCheckWire::TcpConnect {} => Self::TcpConnect,
            HealthCheckWire::TcpTemplate {
                template,
                timeout_ms,
            } => Self::TcpTemplate {
                template,
                timeout_ms,
            },
            HealthCheckWire::TcpSendExpect {
                send,
                expect,
                timeout_ms,
            } => Self::TcpSendExpect {
                send,
                expect,
                timeout_ms,
            },
        })
    }
}

/// A reference to a template of `TCP_CHECK_TEMPLATES`, which only a
/// name the catalogue holds can be.
///
/// It serializes as the name. Decoding a name the catalogue does not
/// hold fails, so a row naming a template this release does not ship
/// reads as having no typed check (the legacy path decides, see
/// [`HealthCheck::reconcile`]), a canonical blob naming one is refused,
/// and an API body naming one is a `422`.
#[derive(Clone, Copy)]
pub struct TcpCheckTemplateName(&'static CheckTemplate);

impl TcpCheckTemplateName {
    /// The reference to the template named `name`, if the release
    /// ships one.
    pub fn new(name: &str) -> Option<Self> {
        tcp_check_template(name).map(Self)
    }

    /// The template's name, as stored.
    pub fn name(&self) -> &'static str {
        self.0.name
    }

    /// The template itself.
    pub fn template(&self) -> &'static CheckTemplate {
        self.0
    }
}

impl PartialEq for TcpCheckTemplateName {
    fn eq(&self, other: &Self) -> bool {
        self.0.name == other.0.name
    }
}

impl Eq for TcpCheckTemplateName {}

impl std::fmt::Debug for TcpCheckTemplateName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("TcpCheckTemplateName")
            .field(&self.0.name)
            .finish()
    }
}

impl Serialize for TcpCheckTemplateName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.name)
    }
}

impl<'de> Deserialize<'de> for TcpCheckTemplateName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        Self::new(&name).ok_or_else(|| {
            let known: Vec<String> = TCP_CHECK_TEMPLATES
                .iter()
                .map(|template| format!("`{}`", template.name))
                .collect();
            D::Error::custom(format!(
                "unknown template `{name}`, expected one of {}",
                known.join(", ")
            ))
        })
    }
}

/// Bytes on the wire of a custom check, in one of two spellings:
/// `{"text": "PING\r\n"}`, the UTF-8 bytes of the string, or
/// `{"hex": "0000000804d2162f"}`, for bytes a JSON string cannot carry
/// as themselves (above `0x7f`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Payload {
    /// The UTF-8 bytes of the string, sent as is.
    Text(String),
    /// An even number of hexadecimal digits, lowercased whichever way
    /// it was read or built.
    Hex(
        #[serde(
            serialize_with = "serialize_lowercase",
            deserialize_with = "deserialize_lowercase"
        )]
        String,
    ),
}

fn serialize_lowercase<S: Serializer>(hex: &str, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex.to_ascii_lowercase())
}

fn deserialize_lowercase<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    Ok(String::deserialize(deserializer)?.to_ascii_lowercase())
}

impl Payload {
    /// The bytes this payload stands for. Fails on a hex spelling that
    /// is not an even number of hexadecimal digits; the reason names
    /// neither the field nor the payload.
    pub fn decode(&self) -> Result<Cow<'_, [u8]>, String> {
        match self {
            Self::Text(text) => Ok(Cow::Borrowed(text.as_bytes())),
            Self::Hex(hex) => decode_hex(hex).map(Cow::Owned),
        }
    }
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("a hex payload is an even number of hexadecimal digits".to_string());
    }
    let digit = |offset: usize| -> Result<u8, String> {
        match hex.as_bytes()[offset] {
            byte @ b'0'..=b'9' => Ok(byte - b'0'),
            byte @ b'a'..=b'f' => Ok(byte - b'a' + 10),
            byte @ b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err(format!(
                "the byte at offset {offset} is not a hexadecimal digit"
            )),
        }
    };
    (0..hex.len())
        .step_by(2)
        .map(|offset| Ok((digit(offset)? << 4) | digit(offset + 1)?))
        .collect()
}

/// One answer a custom check accepts: `{"match": "prefix", "bytes":
/// {"text": "+PONG"}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expectation {
    /// Where the bytes must appear in what the probe reads.
    #[serde(rename = "match")]
    pub anchor: MatchAnchor,
    /// The bytes, matched literally.
    pub bytes: Payload,
}

/// What one send/expect probe does, resolved from a check: the bytes to
/// send, the accepted answers, and the deadline of the whole probe. A
/// template's bytes are borrowed from the catalogue, a custom check's
/// are decoded once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exchange {
    /// What to send once connected, if anything.
    pub send: Option<Cow<'static, [u8]>>,
    /// The accepted answers, any one of them.
    pub expect: Vec<(MatchAnchor, Cow<'static, [u8]>)>,
    /// The deadline of the whole probe: connect, send and read.
    pub timeout: Duration,
}

impl HealthCheck {
    /// The value this definition writes into the legacy
    /// `health_check_path` column: the path of an HTTP check, `None` for
    /// every other kind.
    pub fn legacy_path(&self) -> Option<&str> {
        match self {
            Self::Http { path } => Some(path.as_str()),
            Self::TcpConnect | Self::TcpTemplate { .. } | Self::TcpSendExpect { .. } => None,
        }
    }

    /// The definition a backend row is read as, from its stored typed
    /// definition and its stored legacy path.
    ///
    /// The typed definition is honoured only while its projection onto
    /// the legacy column ([`HealthCheck::legacy_path`]) equals the stored
    /// path. When the two disagree, the row was last written by a binary
    /// that does not know the typed column (a 1.10.6 rollback), and the
    /// path is the truth: `Some(p)` reads as an HTTP check of `p`, `None`
    /// as a TCP connect. "Typed wins" would instead let a re-upgrade
    /// resurrect a probe the operator replaced while rolled back.
    ///
    /// The result's projection always equals `legacy_path`, so a reader
    /// sees one consistent pair whichever branch was taken.
    pub fn reconcile(stored: Option<HealthCheck>, legacy_path: Option<&str>) -> HealthCheck {
        match stored {
            Some(typed) if typed.legacy_path() == legacy_path => typed,
            _ => match legacy_path {
                Some(path) => Self::Http {
                    path: path.to_string(),
                },
                None => Self::TcpConnect,
            },
        }
    }

    /// The `kind` tag this check carries on the wire.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Http { .. } => "http",
            Self::TcpConnect => "tcp_connect",
            Self::TcpTemplate { .. } => "tcp_template",
            Self::TcpSendExpect { .. } => "tcp_send_expect",
        }
    }

    /// The name of the template this check references, if it is one.
    pub fn template_name(&self) -> Option<&'static str> {
        match self {
            Self::TcpTemplate { template, .. } => Some(template.name()),
            Self::Http { .. } | Self::TcpConnect | Self::TcpSendExpect { .. } => None,
        }
    }

    /// Whether this check carries bytes an operator chose, as opposed
    /// to a path, nothing, or a catalogue template (PRD D9).
    ///
    /// Every enforcement point of D9 calls this and never matches a
    /// kind of its own, so a later payload-carrying kind is covered by
    /// its arm here.
    pub fn carries_raw_payload(&self) -> bool {
        match self {
            Self::TcpSendExpect { .. } => true,
            Self::Http { .. } | Self::TcpConnect | Self::TcpTemplate { .. } => false,
        }
    }

    /// Whether the probe exchanges bytes over a plaintext TCP
    /// connection, which a TLS upstream can never answer.
    fn exchanges_plaintext_bytes(&self) -> bool {
        match self {
            Self::TcpTemplate { .. } | Self::TcpSendExpect { .. } => true,
            Self::Http { .. } | Self::TcpConnect => false,
        }
    }

    /// The check's own limits (Story 12.7, D-2), run on every write.
    ///
    /// The error names the field path (`health_check.expect[2].bytes`)
    /// and the limit, never the payload. A template exists by
    /// construction ([`TcpCheckTemplateName`]).
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Http { .. } | Self::TcpConnect => Ok(()),
            Self::TcpTemplate { timeout_ms, .. } => validate_probe_timeout(*timeout_ms),
            Self::TcpSendExpect {
                send,
                expect,
                timeout_ms,
            } => {
                if let Some(send) = send {
                    validate_payload("health_check.send", send, SEND_MAX_BYTES).map_err(
                        |reason| match reason {
                            PayloadRefusal::Empty => "health_check.send: an empty payload is \
                                 refused; leave `send` out to send nothing"
                                .to_string(),
                            PayloadRefusal::Other(reason) => reason,
                        },
                    )?;
                }
                if expect.is_empty() {
                    return Err(
                        "health_check.expect: at least one alternative is required; \
                         a check that expects nothing is `tcp_connect`"
                            .to_string(),
                    );
                }
                if expect.len() > EXPECT_MAX_ALTERNATIVES {
                    return Err(format!(
                        "health_check.expect: {} alternatives, above the limit of \
                         {EXPECT_MAX_ALTERNATIVES}",
                        expect.len()
                    ));
                }
                for (index, expectation) in expect.iter().enumerate() {
                    let field = format!("health_check.expect[{index}].bytes");
                    validate_payload(&field, &expectation.bytes, EXPECT_MAX_BYTES).map_err(
                        |reason| match reason {
                            PayloadRefusal::Empty => {
                                format!("{field}: an empty alternative matches anything")
                            }
                            PayloadRefusal::Other(reason) => reason,
                        },
                    )?;
                }
                validate_probe_timeout(*timeout_ms)
            }
        }
    }

    /// The exchange a send/expect probe of this check performs, or
    /// `None` for a kind that exchanges no bytes.
    ///
    /// Also `None` for a custom payload that does not decode, which only
    /// a row no write validated can hold: such a backend is probed by
    /// TCP connect, never marked down over bytes it could not send. The
    /// timeout is held within the bounds a write accepts whatever the
    /// row says, so no probe outlives [`PROBE_TIMEOUT_MS_MAX`].
    pub fn exchange(&self) -> Option<Exchange> {
        match self {
            Self::Http { .. } | Self::TcpConnect => None,
            Self::TcpTemplate {
                template,
                timeout_ms,
            } => {
                let template = template.template();
                Some(Exchange {
                    send: template.send.map(Cow::Borrowed),
                    expect: template
                        .expect
                        .iter()
                        .map(|expectation| (expectation.anchor, Cow::Borrowed(expectation.bytes)))
                        .collect(),
                    timeout: bounded_probe_timeout(*timeout_ms),
                })
            }
            Self::TcpSendExpect {
                send,
                expect,
                timeout_ms,
            } => {
                let send = match send {
                    Some(payload) => Some(Cow::Owned(payload.decode().ok()?.into_owned())),
                    None => None,
                };
                let expect = expect
                    .iter()
                    .map(|expectation| {
                        let bytes = expectation.bytes.decode().ok()?.into_owned();
                        Some((expectation.anchor, Cow::Owned(bytes)))
                    })
                    .collect::<Option<Vec<_>>>()?;
                Some(Exchange {
                    send,
                    expect,
                    timeout: bounded_probe_timeout(*timeout_ms),
                })
            }
        }
    }
}

/// Why a payload was refused: empty (each field words that its own
/// way), or a reason already naming the field.
enum PayloadRefusal {
    Empty,
    Other(String),
}

fn validate_payload(
    field: &str,
    payload: &Payload,
    max_bytes: usize,
) -> Result<(), PayloadRefusal> {
    let bytes = payload
        .decode()
        .map_err(|reason| PayloadRefusal::Other(format!("{field}: {reason}")))?;
    if bytes.is_empty() {
        return Err(PayloadRefusal::Empty);
    }
    if bytes.len() > max_bytes {
        return Err(PayloadRefusal::Other(format!(
            "{field}: {} bytes, above the limit of {max_bytes}",
            bytes.len()
        )));
    }
    Ok(())
}

fn validate_probe_timeout(timeout_ms: u32) -> Result<(), String> {
    if (PROBE_TIMEOUT_MS_MIN..=PROBE_TIMEOUT_MS_MAX).contains(&timeout_ms) {
        Ok(())
    } else {
        Err(format!(
            "health_check.timeout_ms: {timeout_ms} is outside the accepted range, \
             {PROBE_TIMEOUT_MS_MIN} to {PROBE_TIMEOUT_MS_MAX}"
        ))
    }
}

fn bounded_probe_timeout(timeout_ms: u32) -> Duration {
    Duration::from_millis(u64::from(
        timeout_ms.clamp(PROBE_TIMEOUT_MS_MIN, PROBE_TIMEOUT_MS_MAX),
    ))
}

impl Backend {
    /// Set the active check, keeping the deprecated
    /// `health_check_path` equal to its projection.
    ///
    /// Assigning `health_check` alone leaves the pair disagreeing, and
    /// the store resolves a disagreement in favour of the path
    /// ([`HealthCheck::reconcile`]), so a writer that wants the typed
    /// value to stick goes through this setter.
    pub fn set_health_check(&mut self, check: HealthCheck) {
        self.health_check_path = check.legacy_path().map(str::to_string);
        self.health_check = check;
    }

    /// The one validation of a backend's check, run by every writer
    /// (Story 12.7, D-6): the check's own limits
    /// ([`HealthCheck::validate`]), and the refusal of a plaintext
    /// exchange on a backend with `tls_upstream` on, which could never
    /// succeed against a TLS port.
    pub fn validate_health_check(&self) -> Result<(), String> {
        self.health_check.validate()?;
        if self.tls_upstream && self.health_check.exchanges_plaintext_bytes() {
            return Err(format!(
                "health_check: a `{}` check exchanges plaintext bytes and cannot probe a \
                 backend with tls_upstream on; use `tcp_connect`, or switch tls_upstream off",
                self.health_check.kind()
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(path: &str) -> HealthCheck {
        HealthCheck::Http {
            path: path.to_string(),
        }
    }

    fn template(name: &str) -> HealthCheck {
        HealthCheck::TcpTemplate {
            template: TcpCheckTemplateName::new(name).expect("test setup: a catalogue name"),
            timeout_ms: PROBE_TIMEOUT_MS_DEFAULT,
        }
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// A custom check sending `send` and expecting `expect` as a prefix.
    fn send_expect(send: Option<Payload>, expect: Vec<Expectation>) -> HealthCheck {
        HealthCheck::TcpSendExpect {
            send,
            expect,
            timeout_ms: PROBE_TIMEOUT_MS_DEFAULT,
        }
    }

    fn prefix(bytes: Payload) -> Expectation {
        Expectation {
            anchor: MatchAnchor::Prefix,
            bytes,
        }
    }

    fn text(text: &str) -> Payload {
        Payload::Text(text.to_string())
    }

    /// The `TcpSendExpect` a catalogue template stands for (AC #3).
    fn as_send_expect(template: &CheckTemplate) -> HealthCheck {
        send_expect(
            template.send.map(|bytes| Payload::Hex(hex_of(bytes))),
            template
                .expect
                .iter()
                .map(|expectation| Expectation {
                    anchor: expectation.anchor,
                    bytes: Payload::Hex(hex_of(expectation.bytes)),
                })
                .collect(),
        )
    }

    /// The D-2 matrix of Story 12.1 and the D-5 rows of Story 12.7:
    /// (stored typed, stored path, read as).
    fn matrix() -> Vec<(Option<HealthCheck>, Option<&'static str>, HealthCheck)> {
        let custom = send_expect(Some(text("PING\r\n")), vec![prefix(text("+PONG"))]);
        vec![
            // Written by 1.10.6 or earlier.
            (None, None, HealthCheck::TcpConnect),
            (None, Some("/h"), http("/h")),
            // Written by 1.11.0.
            (Some(http("/h")), Some("/h"), http("/h")),
            (Some(HealthCheck::TcpConnect), None, HealthCheck::TcpConnect),
            (Some(template("redis_ping")), None, template("redis_ping")),
            (Some(custom.clone()), None, custom.clone()),
            // 1.10.6 edited the path after 1.11.0 wrote the row.
            (Some(http("/h")), Some("/x"), http("/x")),
            // 1.10.6 cleared the path.
            (Some(http("/h")), None, HealthCheck::TcpConnect),
            // 1.10.6 set a path on a TCP-checked backend.
            (Some(HealthCheck::TcpConnect), Some("/x"), http("/x")),
            (Some(template("redis_ping")), Some("/x"), http("/x")),
            (Some(custom), Some("/x"), http("/x")),
            // A kind or a template this binary does not know is read as
            // absent by the store, so it is the `None` rows above; pinned
            // by `a_stored_definition_this_release_refuses_reads_by_the_legacy_path`.
        ]
    }

    #[test]
    fn reconcile_reads_every_row_of_the_rollback_matrix() {
        for (stored, path, expected) in matrix() {
            let got = HealthCheck::reconcile(stored.clone(), path);
            assert_eq!(got, expected, "stored {stored:?}, path {path:?}");
            assert_eq!(
                got.legacy_path(),
                path,
                "the reconciled definition projects onto the stored path"
            );
        }
    }

    #[test]
    fn the_wire_shape_is_tagged_by_kind() {
        assert_eq!(
            serde_json::to_value(http("/healthz")).expect("serialize"),
            serde_json::json!({"kind": "http", "path": "/healthz"})
        );
        assert_eq!(
            serde_json::to_value(HealthCheck::TcpConnect).expect("serialize"),
            serde_json::json!({"kind": "tcp_connect"})
        );
        let parsed: HealthCheck =
            serde_json::from_str(r#"{"kind":"tcp_connect"}"#).expect("tcp_connect parses");
        assert_eq!(parsed, HealthCheck::TcpConnect);
        assert!(serde_json::from_str::<HealthCheck>(r#"{"kind":"http"}"#).is_err());
        assert!(
            serde_json::from_str::<HealthCheck>(r#"{"kind":"http","path":"/h","port":1}"#).is_err(),
            "an unknown field is refused"
        );
        assert!(serde_json::from_str::<HealthCheck>(r#"{"kind":"icmp"}"#).is_err());
    }

    /// The wire examples of Story 12.7 D-1, read and written back.
    #[test]
    fn the_send_expect_kinds_round_trip_their_documented_wire_shapes() {
        let parsed: HealthCheck =
            serde_json::from_str(r#"{"kind":"tcp_template","template":"redis_ping"}"#)
                .expect("a template parses");
        assert_eq!(parsed, template("redis_ping"));
        assert_eq!(
            serde_json::to_value(&parsed).expect("serialize"),
            serde_json::json!({
                "kind": "tcp_template",
                "template": "redis_ping",
                "timeout_ms": PROBE_TIMEOUT_MS_DEFAULT,
            })
        );

        let postgres = serde_json::json!({
            "kind": "tcp_send_expect",
            "send": {"hex": "0000000804d2162f"},
            "expect": [
                {"match": "prefix", "bytes": {"hex": "53"}},
                {"match": "prefix", "bytes": {"hex": "4e"}},
            ],
            "timeout_ms": 2000,
        });
        let parsed: HealthCheck =
            serde_json::from_value(postgres.clone()).expect("a custom exchange parses");
        assert_eq!(serde_json::to_value(&parsed).expect("serialize"), postgres);

        let banner: HealthCheck = serde_json::from_str(
            r#"{"kind":"tcp_send_expect","expect":[{"match":"prefix","bytes":{"text":"220"}}]}"#,
        )
        .expect("a check sending nothing parses");
        assert_eq!(
            banner,
            send_expect(None, vec![prefix(text("220"))]),
            "absent send sends nothing, absent timeout is the default"
        );
        assert_eq!(
            serde_json::to_value(&banner).expect("serialize"),
            serde_json::json!({
                "kind": "tcp_send_expect",
                "expect": [{"match": "prefix", "bytes": {"text": "220"}}],
                "timeout_ms": PROBE_TIMEOUT_MS_DEFAULT,
            }),
            "an absent send stays absent"
        );
    }

    #[test]
    fn an_unknown_template_or_kind_does_not_decode() {
        assert!(serde_json::from_str::<HealthCheck>(
            r#"{"kind":"tcp_template","template":"memcached_stats"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<HealthCheck>(r#"{"kind":"udp_send_expect"}"#).is_err());
        assert!(serde_json::from_str::<HealthCheck>(
            r#"{"kind":"tcp_send_expect","expect":[{"match":"suffix","bytes":{"text":"x"}}]}"#
        )
        .is_err());
    }

    #[test]
    fn a_payload_is_exactly_one_of_text_or_hex() {
        assert_eq!(
            serde_json::from_str::<Payload>(r#"{"text":"PING\r\n"}"#)
                .expect("text parses")
                .decode()
                .expect("decodes")
                .as_ref(),
            b"PING\r\n"
        );
        assert_eq!(
            serde_json::from_str::<Payload>(r#"{"hex":"04d2162f"}"#)
                .expect("hex parses")
                .decode()
                .expect("decodes")
                .as_ref(),
            [0x04, 0xd2, 0x16, 0x2f]
        );
        for refused in [r#"{"text":"a","hex":"61"}"#, r#"{}"#, r#""PING""#] {
            assert!(
                serde_json::from_str::<Payload>(refused).is_err(),
                "{refused} is refused from text"
            );
            let value: serde_json::Value = serde_json::from_str(refused).expect("valid JSON");
            assert!(
                serde_json::from_value::<Payload>(value).is_err(),
                "{refused} is refused from a value"
            );
        }
    }

    #[test]
    fn a_hex_payload_is_lowercased_whichever_way_it_comes_in() {
        let read: Payload = serde_json::from_str(r#"{"hex":"04D2162F"}"#).expect("parses");
        assert_eq!(read, Payload::Hex("04d2162f".to_string()));
        assert_eq!(
            serde_json::to_value(Payload::Hex("ABCDEF".to_string())).expect("serialize"),
            serde_json::json!({"hex": "abcdef"})
        );
    }

    #[test]
    fn every_template_is_a_valid_send_expect_and_probes_the_same_bytes() {
        for catalogued in TCP_CHECK_TEMPLATES {
            let custom = as_send_expect(catalogued);
            assert_eq!(custom.validate(), Ok(()), "{}", catalogued.name);
            assert_eq!(
                custom.exchange(),
                template(catalogued.name).exchange(),
                "{}",
                catalogued.name
            );
        }
    }

    /// The bytes of a payload of `len` decoded bytes, in both spellings.
    fn payloads_of(len: usize) -> [Payload; 2] {
        [
            Payload::Text("a".repeat(len)),
            Payload::Hex("61".repeat(len)),
        ]
    }

    fn refusal(check: &HealthCheck) -> String {
        check.validate().expect_err("refused")
    }

    #[test]
    fn send_is_refused_empty_or_past_its_limit_and_accepted_at_it() {
        for payload in payloads_of(SEND_MAX_BYTES) {
            let check = send_expect(Some(payload), vec![prefix(text("+"))]);
            assert_eq!(check.validate(), Ok(()));
        }
        for payload in payloads_of(SEND_MAX_BYTES + 1) {
            let check = send_expect(Some(payload), vec![prefix(text("+"))]);
            let reason = refusal(&check);
            assert!(reason.starts_with("health_check.send:"), "{reason}");
            assert!(reason.contains(&SEND_MAX_BYTES.to_string()), "{reason}");
        }
        for payload in payloads_of(0) {
            let check = send_expect(Some(payload), vec![prefix(text("+"))]);
            assert!(refusal(&check).starts_with("health_check.send:"));
        }
    }

    #[test]
    fn expect_is_refused_empty_or_past_its_limits_and_accepted_at_them() {
        let one = || prefix(text("+"));
        assert!(refusal(&send_expect(None, vec![])).starts_with("health_check.expect:"));

        let at_limit = send_expect(None, (0..EXPECT_MAX_ALTERNATIVES).map(|_| one()).collect());
        assert_eq!(at_limit.validate(), Ok(()));
        let past = send_expect(None, (0..=EXPECT_MAX_ALTERNATIVES).map(|_| one()).collect());
        let reason = refusal(&past);
        assert!(reason.starts_with("health_check.expect:"), "{reason}");
        assert!(
            reason.contains(&EXPECT_MAX_ALTERNATIVES.to_string()),
            "{reason}"
        );

        for payload in payloads_of(EXPECT_MAX_BYTES) {
            assert_eq!(send_expect(None, vec![prefix(payload)]).validate(), Ok(()));
        }
        for payload in payloads_of(EXPECT_MAX_BYTES + 1) {
            let reason = refusal(&send_expect(None, vec![one(), one(), prefix(payload)]));
            assert!(
                reason.starts_with("health_check.expect[2].bytes:"),
                "{reason}"
            );
            assert!(reason.contains(&EXPECT_MAX_BYTES.to_string()), "{reason}");
        }
        for payload in payloads_of(0) {
            let reason = refusal(&send_expect(None, vec![one(), prefix(payload)]));
            assert!(
                reason.starts_with("health_check.expect[1].bytes:"),
                "{reason}"
            );
        }
    }

    #[test]
    fn a_malformed_hex_payload_is_refused_naming_its_field() {
        for malformed in ["0", "0g", "abc", "zz"] {
            let check = send_expect(
                Some(Payload::Hex(malformed.to_string())),
                vec![prefix(text("+"))],
            );
            assert!(
                refusal(&check).starts_with("health_check.send:"),
                "{malformed}"
            );
            let check = send_expect(None, vec![prefix(Payload::Hex(malformed.to_string()))]);
            assert!(
                refusal(&check).starts_with("health_check.expect[0].bytes:"),
                "{malformed}"
            );
        }
    }

    #[test]
    fn the_timeout_is_accepted_within_its_bounds_and_refused_outside() {
        let with_timeout = |timeout_ms: u32| {
            [
                HealthCheck::TcpTemplate {
                    template: TcpCheckTemplateName::new("smtp_banner").expect("catalogued"),
                    timeout_ms,
                },
                HealthCheck::TcpSendExpect {
                    send: None,
                    expect: vec![prefix(text("220"))],
                    timeout_ms,
                },
            ]
        };
        for accepted in [PROBE_TIMEOUT_MS_MIN, PROBE_TIMEOUT_MS_MAX] {
            for check in with_timeout(accepted) {
                assert_eq!(check.validate(), Ok(()), "{accepted}");
            }
        }
        for refused in [PROBE_TIMEOUT_MS_MIN - 1, PROBE_TIMEOUT_MS_MAX + 1] {
            for check in with_timeout(refused) {
                let reason = refusal(&check);
                assert!(reason.starts_with("health_check.timeout_ms:"), "{reason}");
                assert!(
                    reason.contains(&PROBE_TIMEOUT_MS_MIN.to_string())
                        && reason.contains(&PROBE_TIMEOUT_MS_MAX.to_string()),
                    "{reason}"
                );
            }
        }
    }

    fn backend_with(check: HealthCheck, tls_upstream: bool) -> Backend {
        let mut backend = crate::models::sample_stream_backend("b-1", "192.0.2.10:6379");
        backend.tls_upstream = tls_upstream;
        backend.set_health_check(check);
        backend
    }

    #[test]
    fn a_plaintext_exchange_is_refused_on_a_tls_upstream() {
        for check in [
            template("redis_ping"),
            send_expect(None, vec![prefix(text("220"))]),
        ] {
            assert_eq!(
                backend_with(check.clone(), false).validate_health_check(),
                Ok(())
            );
            let reason = backend_with(check.clone(), true)
                .validate_health_check()
                .expect_err("refused on a TLS upstream");
            assert!(
                reason.contains("health_check") && reason.contains("tls_upstream"),
                "{reason}"
            );
        }
        for check in [http("/healthz"), HealthCheck::TcpConnect] {
            assert_eq!(backend_with(check, true).validate_health_check(), Ok(()));
        }
    }

    #[test]
    fn only_a_custom_exchange_carries_a_raw_payload() {
        for check in samples() {
            assert_eq!(
                check.carries_raw_payload(),
                check.kind() == "tcp_send_expect",
                "{check:?}"
            );
        }
    }

    #[test]
    fn the_kind_is_the_wire_tag() {
        for check in samples() {
            assert_eq!(
                serde_json::to_value(&check).expect("serialize")["kind"],
                serde_json::json!(check.kind())
            );
        }
    }

    #[test]
    fn a_custom_payload_that_does_not_decode_exchanges_nothing() {
        let check = send_expect(Some(Payload::Hex("0".to_string())), vec![prefix(text("+"))]);
        assert_eq!(check.exchange(), None);
        let check = send_expect(None, vec![prefix(Payload::Hex("zz".to_string()))]);
        assert_eq!(check.exchange(), None);
    }

    #[test]
    fn the_exchange_timeout_is_held_within_the_written_bounds() {
        for (stored, expected) in [
            (0, PROBE_TIMEOUT_MS_MIN),
            (u32::MAX, PROBE_TIMEOUT_MS_MAX),
            (2_000, 2_000),
        ] {
            let check = HealthCheck::TcpSendExpect {
                send: None,
                expect: vec![prefix(text("220"))],
                timeout_ms: stored,
            };
            assert_eq!(
                check.exchange().expect("an exchange").timeout,
                Duration::from_millis(u64::from(expected))
            );
        }
    }

    /// One value of each kind.
    fn samples() -> Vec<HealthCheck> {
        vec![
            http("/healthz"),
            HealthCheck::TcpConnect,
            template("redis_ping"),
            send_expect(Some(text("PING\r\n")), vec![prefix(text("+PONG"))]),
        ]
    }

    /// Every `kind` tag the type accepts, read from serde's refusal of an
    /// unknown one rather than typed again here.
    fn accepted_kinds() -> Vec<String> {
        const PROBE: &str = "__lorica_kind_probe__";
        let error = serde_json::from_value::<HealthCheck>(serde_json::json!({ "kind": PROBE }))
            .expect_err("an unknown kind is refused");
        // "unknown variant `X`, expected `a` or `b`": every odd-indexed
        // split on a backtick is a quoted name, the first is the probe.
        let message = error.to_string();
        let mut kinds: Vec<String> = message
            .split('`')
            .skip(1)
            .step_by(2)
            .map(str::to_string)
            .collect();
        assert_eq!(kinds.first().map(String::as_str), Some(PROBE), "{message}");
        kinds.remove(0);
        kinds.sort();
        kinds
    }

    #[test]
    fn the_samples_cover_every_kind() {
        let mut sampled: Vec<String> = samples()
            .iter()
            .map(|check| check.kind().to_string())
            .collect();
        sampled.sort();
        assert_eq!(sampled, accepted_kinds(), "add a sample for the new kind");
    }

    #[test]
    fn every_kind_refuses_an_unknown_field() {
        for check in samples() {
            let mut value = serde_json::to_value(&check).expect("serialize");
            let parsed: HealthCheck =
                serde_json::from_value(value.clone()).expect("the kind's own shape parses");
            assert_eq!(parsed, check);
            value
                .as_object_mut()
                .expect("a health check is an object")
                .insert("expect_status".to_string(), serde_json::json!(204));
            assert!(
                serde_json::from_value::<HealthCheck>(value.clone()).is_err(),
                "{value} carries a field its kind does not have and must be refused"
            );
        }
    }

    #[test]
    fn a_tcp_connect_carrying_an_http_path_is_refused() {
        assert!(
            serde_json::from_str::<HealthCheck>(r#"{"kind":"tcp_connect","path":"/x"}"#).is_err()
        );
    }

    /// What a newer release might store, read back by this one: the
    /// definition it cannot parse reads as absent (a WARN, never
    /// `Corrupt`), and the legacy path decides, as for a 1.10.6 rollback.
    #[test]
    fn a_stored_definition_this_release_refuses_reads_by_the_legacy_path() {
        let store = crate::store::ConfigStore::open_in_memory().expect("test setup: store");
        let mut backend = crate::models::sample_stream_backend("b-1", "192.0.2.10:80");
        backend.set_health_check(http("/ready"));
        store.create_backend(&backend).expect("test setup: backend");
        for (stored, path, read_as) in [
            (
                r#"{"kind":"tcp_connect","timeout_ms":500}"#,
                None,
                HealthCheck::TcpConnect,
            ),
            (
                r#"{"kind":"http","path":"/ready","expect_status":204}"#,
                Some("/ready"),
                http("/ready"),
            ),
            (
                r#"{"kind":"udp_probe","payload":"ping"}"#,
                None,
                HealthCheck::TcpConnect,
            ),
            (
                r#"{"kind":"tcp_template","template":"memcached_stats","timeout_ms":500}"#,
                None,
                HealthCheck::TcpConnect,
            ),
            (
                r#"{"kind":"tcp_send_expect","expect":[{"match":"regex","bytes":{"text":"x"}}]}"#,
                None,
                HealthCheck::TcpConnect,
            ),
        ] {
            store
                .conn
                .execute(
                    "UPDATE backends SET health_check_json = ?1, health_check_path = ?2 \
                     WHERE id = 'b-1'",
                    rusqlite::params![stored, path],
                )
                .expect("test setup: a newer release's row");
            let read = store
                .get_backend("b-1")
                .expect("an unknown definition is not a corrupt row")
                .expect("the backend is there");
            assert_eq!(read.health_check, read_as, "stored {stored}");
            assert_eq!(read.health_check_path.as_deref(), path);
        }
    }

    #[test]
    fn the_setter_keeps_the_legacy_path_in_step() {
        let mut backend = crate::models::sample_stream_backend("b-1", "192.0.2.10:80");
        assert_eq!(backend.health_check, HealthCheck::TcpConnect);
        backend.set_health_check(http("/ready"));
        assert_eq!(backend.health_check_path.as_deref(), Some("/ready"));
        backend.set_health_check(template("redis_ping"));
        assert_eq!(backend.health_check_path, None);
        backend.set_health_check(HealthCheck::TcpConnect);
        assert_eq!(backend.health_check_path, None);
        assert_eq!(backend.health_check, HealthCheck::TcpConnect);
    }

    #[test]
    fn a_backend_without_health_check_deserialises_to_tcp_connect() {
        let backend: Backend = serde_json::from_value(serde_json::json!({
            "id": "b-1",
            "address": "192.0.2.10:80",
            "weight": 1,
            "health_status": "healthy",
            "health_check_enabled": true,
            "health_check_interval_s": 10,
            "lifecycle_state": "normal",
            "active_connections": 0,
            "tls_upstream": false,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }))
        .expect("test setup: a backend without health_check deserialises");
        assert_eq!(backend.health_check, HealthCheck::TcpConnect);
    }
}
