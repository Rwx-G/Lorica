//! The automation environment resource (Story 10.4) and the ownership
//! mark it leaves on the routes and backends it creates.
//!
//! An environment is the composite a CI pipeline asks for in one call:
//! a route, its backends, the certificate binding, and a lifetime. The
//! route and backend rows are ordinary rows; what makes them part of an
//! environment is the [`ManagedBy`] mark, which a dashboard reads to
//! show the badge and refuse in-place edits (AC #8), and the
//! `automation_environments` row, which carries what the route row
//! cannot: who created it, how the certificate is chosen, and when the
//! reaper may collect it.
//!
//! Both replicate. A follower serving the environment's route needs to
//! know the environment exists, or its own dashboard would show a plain
//! route an operator may edit by hand, and the next `PUT` from the
//! pipeline would silently overwrite that edit.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Longest environment name accepted: an RFC 1123 label.
pub const AUTOMATION_ENVIRONMENT_NAME_MAX_LEN: usize = 63;

/// Most labels one environment may carry.
pub const AUTOMATION_ENVIRONMENT_MAX_LABELS: usize = 16;

/// Byte ceiling on a label key and on a label value.
pub const AUTOMATION_ENVIRONMENT_LABEL_MAX_LEN: usize = 128;

/// The label that opens an environment to every automation principal,
/// when its value is exactly [`AUTOMATION_ENVIRONMENT_SHARED_VALUE`].
pub const AUTOMATION_ENVIRONMENT_SHARED_LABEL: &str = "shared";

/// The one value of [`AUTOMATION_ENVIRONMENT_SHARED_LABEL`] that opens
/// an environment. Anything else, `"yes"` and `"True"` included, does
/// not: an authorization rule must not be reachable by a near miss.
pub const AUTOMATION_ENVIRONMENT_SHARED_VALUE: &str = "true";

/// Who manages a route or a backend, when it is not the operator.
///
/// A closed enum with one variant rather than a string column, so the
/// next manager is a variant here and not a second nullable column on
/// two tables. `None` on the row means operator-managed, which is
/// every row written before Story 10.4 and every row the dashboard
/// creates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagedBy {
    /// Created by the automation API on behalf of the named
    /// environment. The dashboard shows the badge with this name and
    /// refuses in-place edits (AC #8).
    Automation {
        /// The `automation_environments.name` this row belongs to.
        environment: String,
    },
}

/// The kind of principal that may create an environment.
///
/// Declared with both variants now so the enum does not move when
/// Story 10.5 swaps the static token for an OIDC ID token: a follower on
/// 10.4 must already decode the 10.5 shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerKind {
    /// A Story 10.3 automation token; the principal is the token NAME.
    StaticToken,
    /// A Story 10.5 OIDC project; the principal is the project path.
    OidcProject,
}

/// The identity that created an environment, and therefore the rule
/// for who may touch it (see [`may_access`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentOwner {
    /// What sort of principal `principal` names.
    pub kind: OwnerKind,
    /// The token name for a static token, the project path for OIDC.
    pub principal: String,
}

/// The CI job an environment was last written by, taken from a GitLab
/// ID token (Story 10.5 AC #3).
///
/// Every field is a claim the token stated and the issuer signed, so
/// the row can answer "which pipeline of which project put this here"
/// after the token itself is gone. `None` on the environment means the
/// last write came from a static token, which states nothing about the
/// job behind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineIdentity {
    /// The `project_path` claim, which is also the ownership principal.
    pub project_path: String,
    /// The `ref` claim: the branch or tag the job ran for.
    #[serde(rename = "ref", default)]
    pub git_ref: Option<String>,
    /// The `pipeline_id` claim.
    #[serde(default)]
    pub pipeline_id: Option<String>,
    /// The `job_id` claim.
    #[serde(default)]
    pub job_id: Option<String>,
    /// The `user_login` claim: who triggered the pipeline.
    #[serde(default)]
    pub user_login: Option<String>,
}

/// How an environment's certificate is chosen.
///
/// `Auto` is a stored MODE, re-resolved at every configuration snapshot
/// build, so replacing the wildcard certificate with a new id moves
/// every environment over without a pipeline re-run. The route row still
/// carries the resolved `certificate_id`, so the proxy's configuration
/// path never sees this enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    content = "certificate_id",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CertificateMode {
    /// Pick the certificate covering the hostname at snapshot build.
    Auto,
    /// Always bind this certificate id.
    Explicit(String),
}

/// One row of `automation_environments`: the part of a review app that
/// the route row cannot carry.
///
/// The route and backend rows themselves are ordinary rows marked with
/// [`ManagedBy::Automation`]; this row names the route and adds the
/// owner, the certificate mode, the labels and the expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationEnvironment {
    /// The environment name, an RFC 1123 label and the primary key.
    pub name: String,
    /// The `Route.id` this environment owns. The row cascades away
    /// with the route.
    pub route_id: String,
    /// Who created the environment and may read, update or delete it.
    pub owner: EnvironmentOwner,
    /// How the certificate on the route is chosen.
    pub certificate_mode: CertificateMode,
    /// Free-form labels, at most [`AUTOMATION_ENVIRONMENT_MAX_LABELS`]
    /// entries of at most [`AUTOMATION_ENVIRONMENT_LABEL_MAX_LEN`] bytes
    /// each side. A `BTreeMap` so the row serialises the same way on
    /// every node, which the canonical blob depends on.
    pub labels: BTreeMap<String, String>,
    /// When the reaper may collect the environment.
    pub expires_at: DateTime<Utc>,
    /// First-insert timestamp, bound from the model so a follower
    /// re-encodes the control plane's bytes.
    pub created_at: DateTime<Utc>,
    /// Last-write timestamp.
    pub updated_at: DateTime<Utc>,
    /// The pipeline identifier of the last `PUT`, when the caller
    /// supplied one.
    pub last_pipeline: Option<String>,
    /// The CI job behind the last `PUT`, when it authenticated with an
    /// ID token. `default` so a row written before Story 10.5 decodes.
    #[serde(default)]
    pub pipeline: Option<PipelineIdentity>,
}

impl AutomationEnvironment {
    /// Check the invariants a row must hold regardless of who wrote it.
    ///
    /// The name must be an RFC 1123 label: 1 to
    /// [`AUTOMATION_ENVIRONMENT_NAME_MAX_LEN`] characters of lowercase
    /// ASCII letters, digits and hyphens, neither starting nor ending
    /// with a hyphen. Lowercase is required rather than folded because
    /// the name becomes a `group_name` and a hostname slug, both of
    /// which are compared byte for byte.
    ///
    /// # Errors
    ///
    /// Returns the operator-facing reason when the name breaks the
    /// label rule, when `route_id` or the owner principal is empty,
    /// when there are more than [`AUTOMATION_ENVIRONMENT_MAX_LABELS`]
    /// labels, when a label key is empty, when a key or a value exceeds
    /// [`AUTOMATION_ENVIRONMENT_LABEL_MAX_LEN`] bytes, or when
    /// [`CertificateMode::Explicit`] carries an empty id.
    ///
    /// ```
    /// use lorica_config::models::AutomationEnvironment;
    /// # fn demo(mut environment: AutomationEnvironment) {
    /// environment.name = "Review-42".to_string();
    /// // An uppercase letter is not a near miss the store folds away.
    /// assert!(environment.validate().is_err());
    /// # }
    /// ```
    pub fn validate(&self) -> Result<(), String> {
        validate_environment_name(&self.name)?;
        if self.route_id.is_empty() {
            return Err("environment must name the route it owns (route_id)".to_string());
        }
        if self.owner.principal.is_empty() {
            return Err("environment must name the principal that created it".to_string());
        }
        if let CertificateMode::Explicit(id) = &self.certificate_mode {
            if id.is_empty() {
                return Err(
                    "certificate mode `explicit` must carry a certificate id; use `auto` \
                     to let Lorica pick one"
                        .to_string(),
                );
            }
        }
        if self.labels.len() > AUTOMATION_ENVIRONMENT_MAX_LABELS {
            return Err(format!(
                "at most {AUTOMATION_ENVIRONMENT_MAX_LABELS} labels are allowed"
            ));
        }
        for (key, value) in &self.labels {
            if key.is_empty() {
                return Err("a label key cannot be empty".to_string());
            }
            if key.len() > AUTOMATION_ENVIRONMENT_LABEL_MAX_LEN {
                return Err(format!(
                    "label key exceeds {AUTOMATION_ENVIRONMENT_LABEL_MAX_LEN} bytes"
                ));
            }
            if value.len() > AUTOMATION_ENVIRONMENT_LABEL_MAX_LEN {
                return Err(format!(
                    "label `{key}` value exceeds {AUTOMATION_ENVIRONMENT_LABEL_MAX_LEN} bytes"
                ));
            }
        }
        Ok(())
    }

    /// Whether the label set opens this environment to every principal.
    pub fn is_shared(&self) -> bool {
        labels_mark_shared(&self.labels)
    }
}

/// The RFC 1123 label rule for an environment name.
///
/// # Errors
///
/// Returns the operator-facing reason.
pub fn validate_environment_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > AUTOMATION_ENVIRONMENT_NAME_MAX_LEN {
        return Err(format!(
            "environment name must be 1 to {AUTOMATION_ENVIRONMENT_NAME_MAX_LEN} characters"
        ));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err("environment name cannot start or end with a hyphen".to_string());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(
            "environment name must be an RFC 1123 label: lowercase ASCII letters, digits \
             and hyphens"
                .to_string(),
        );
    }
    Ok(())
}

/// The part of a principal before its first `-`, or the whole principal
/// when it has none.
///
/// `acme-ci`, `acme-deploy` and `acme` all share the prefix `acme`;
/// `acmecorp` does not. A principal that starts with a hyphen has an
/// empty prefix, which [`may_access`] never matches.
pub fn principal_prefix(principal: &str) -> &str {
    principal.split('-').next().unwrap_or(principal)
}

/// Whether a label set carries `shared = "true"`.
fn labels_mark_shared(labels: &BTreeMap<String, String>) -> bool {
    labels
        .get(AUTOMATION_ENVIRONMENT_SHARED_LABEL)
        .is_some_and(|value| value == AUTOMATION_ENVIRONMENT_SHARED_VALUE)
}

/// Whether a caller may read, update or delete an environment
/// (Story 10.4 AC #6).
///
/// The caller may when it is a principal of the SAME kind as the owner
/// and shares its prefix (see [`principal_prefix`]), or when the
/// environment carries the label
/// [`AUTOMATION_ENVIRONMENT_SHARED_LABEL`] with the exact value
/// [`AUTOMATION_ENVIRONMENT_SHARED_VALUE`].
///
/// A different kind never matches, even on an identical principal
/// string: a static token named `acme` and an OIDC project `acme` were
/// issued by different authorities and are not the same owner. An empty
/// prefix matches nothing, so a principal beginning with a hyphen cannot
/// reach another such principal's environments by accident.
///
/// The rule is narrow on purpose. Two projects sharing a Lorica must not
/// be able to delete each other's review apps, and the same check gates
/// all three verbs: a rule enforced on delete but not on update is not a
/// rule.
///
/// ```
/// use std::collections::BTreeMap;
/// use lorica_config::models::{may_access, EnvironmentOwner, OwnerKind};
///
/// let owner = EnvironmentOwner {
///     kind: OwnerKind::StaticToken,
///     principal: "acme-ci".to_string(),
/// };
/// let labels = BTreeMap::new();
/// assert!(may_access(&owner, "acme-deploy", OwnerKind::StaticToken, &labels));
/// assert!(!may_access(&owner, "globex-ci", OwnerKind::StaticToken, &labels));
/// assert!(!may_access(&owner, "acme-ci", OwnerKind::OidcProject, &labels));
/// ```
pub fn may_access(
    owner: &EnvironmentOwner,
    caller_principal: &str,
    caller_kind: OwnerKind,
    labels: &BTreeMap<String, String>,
) -> bool {
    if labels_mark_shared(labels) {
        return true;
    }
    if owner.kind != caller_kind {
        return false;
    }
    let prefix = principal_prefix(&owner.principal);
    !prefix.is_empty() && prefix == principal_prefix(caller_principal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("test setup: valid timestamp")
            .with_timezone(&Utc)
    }

    fn environment() -> AutomationEnvironment {
        AutomationEnvironment {
            name: "pr-42".to_string(),
            route_id: "route-1".to_string(),
            owner: EnvironmentOwner {
                kind: OwnerKind::StaticToken,
                principal: "acme-ci".to_string(),
            },
            certificate_mode: CertificateMode::Auto,
            labels: BTreeMap::new(),
            expires_at: fixed_now(),
            created_at: fixed_now(),
            updated_at: fixed_now(),
            last_pipeline: None,
            pipeline: None,
        }
    }

    fn owner(kind: OwnerKind, principal: &str) -> EnvironmentOwner {
        EnvironmentOwner {
            kind,
            principal: principal.to_string(),
        }
    }

    fn labels(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    // ---- The name rule ----

    #[test]
    fn a_well_formed_environment_validates() {
        assert_eq!(environment().validate(), Ok(()));
    }

    #[test]
    fn the_name_is_an_rfc_1123_label() {
        for good in ["a", "pr-42", "review-app-2026", "x".repeat(63).as_str()] {
            assert_eq!(validate_environment_name(good), Ok(()), "{good}");
        }
        for bad in [
            "",
            "-pr",
            "pr-",
            "PR-42",
            "pr_42",
            "pr.42",
            "pr 42",
            "x".repeat(64).as_str(),
        ] {
            assert!(validate_environment_name(bad).is_err(), "{bad:?}");
        }
    }

    // ---- The label caps ----

    #[test]
    fn at_most_sixteen_labels_are_accepted() {
        let mut env = environment();
        env.labels = (0..AUTOMATION_ENVIRONMENT_MAX_LABELS)
            .map(|i| (format!("k{i}"), "v".to_string()))
            .collect();
        assert_eq!(env.validate(), Ok(()));
        env.labels
            .insert("one-too-many".to_string(), "v".to_string());
        assert!(env.validate().is_err());
    }

    #[test]
    fn a_label_key_or_value_over_the_byte_cap_is_refused() {
        let mut env = environment();
        env.labels = labels(&[(&"k".repeat(AUTOMATION_ENVIRONMENT_LABEL_MAX_LEN), "v")]);
        assert_eq!(env.validate(), Ok(()));
        env.labels = labels(&[(&"k".repeat(AUTOMATION_ENVIRONMENT_LABEL_MAX_LEN + 1), "v")]);
        assert!(env.validate().is_err());
        env.labels = labels(&[("k", &"v".repeat(AUTOMATION_ENVIRONMENT_LABEL_MAX_LEN + 1))]);
        assert!(env.validate().is_err());
        env.labels = labels(&[("", "v")]);
        assert!(env.validate().is_err());
    }

    #[test]
    fn an_explicit_certificate_mode_must_carry_an_id() {
        let mut env = environment();
        env.certificate_mode = CertificateMode::Explicit(String::new());
        assert!(env.validate().is_err());
        env.certificate_mode = CertificateMode::Explicit("cert-1".to_string());
        assert_eq!(env.validate(), Ok(()));
    }

    #[test]
    fn an_empty_route_or_principal_is_refused() {
        let mut env = environment();
        env.route_id.clear();
        assert!(env.validate().is_err());
        let mut env = environment();
        env.owner.principal.clear();
        assert!(env.validate().is_err());
    }

    // ---- The ownership matrix (AC #6) ----

    #[test]
    fn same_kind_and_same_prefix_may_access() {
        let owner = owner(OwnerKind::StaticToken, "acme-ci");
        let none = BTreeMap::new();
        assert!(may_access(&owner, "acme-ci", OwnerKind::StaticToken, &none));
        assert!(may_access(
            &owner,
            "acme-deploy",
            OwnerKind::StaticToken,
            &none
        ));
        assert!(may_access(&owner, "acme", OwnerKind::StaticToken, &none));
    }

    #[test]
    fn same_kind_but_a_different_prefix_may_not() {
        let owner = owner(OwnerKind::StaticToken, "acme-ci");
        let none = BTreeMap::new();
        assert!(!may_access(
            &owner,
            "globex-ci",
            OwnerKind::StaticToken,
            &none
        ));
        assert!(
            !may_access(&owner, "acmecorp-ci", OwnerKind::StaticToken, &none),
            "the prefix is the whole first segment, not a string prefix"
        );
    }

    #[test]
    fn a_different_kind_never_matches_even_on_an_identical_principal() {
        let none = BTreeMap::new();
        let token = owner(OwnerKind::StaticToken, "acme");
        assert!(!may_access(&token, "acme", OwnerKind::OidcProject, &none));
        let project = owner(OwnerKind::OidcProject, "acme");
        assert!(!may_access(&project, "acme", OwnerKind::StaticToken, &none));
    }

    #[test]
    fn the_shared_label_set_to_true_opens_the_environment() {
        let owner = owner(OwnerKind::StaticToken, "acme-ci");
        let shared = labels(&[("shared", "true")]);
        assert!(may_access(
            &owner,
            "globex-ci",
            OwnerKind::StaticToken,
            &shared
        ));
        assert!(may_access(
            &owner,
            "globex/app",
            OwnerKind::OidcProject,
            &shared
        ));
    }

    #[test]
    fn the_shared_label_with_any_other_value_does_not() {
        let owner = owner(OwnerKind::StaticToken, "acme-ci");
        for value in ["yes", "True", "TRUE", "1", "", " true"] {
            let not_shared = labels(&[("shared", value)]);
            assert!(
                !may_access(&owner, "globex-ci", OwnerKind::StaticToken, &not_shared),
                "shared={value:?} must not open the environment"
            );
        }
        let other_key = labels(&[("Shared", "true")]);
        assert!(!may_access(
            &owner,
            "globex-ci",
            OwnerKind::StaticToken,
            &other_key
        ));
    }

    #[test]
    fn an_empty_prefix_matches_nothing() {
        let owner = owner(OwnerKind::StaticToken, "-ci");
        let none = BTreeMap::new();
        assert!(!may_access(
            &owner,
            "-deploy",
            OwnerKind::StaticToken,
            &none
        ));
        assert!(!may_access(&owner, "-ci", OwnerKind::StaticToken, &none));
    }

    #[test]
    fn the_prefix_is_the_text_before_the_first_hyphen() {
        assert_eq!(principal_prefix("acme-ci-eu"), "acme");
        assert_eq!(principal_prefix("acme"), "acme");
        assert_eq!(principal_prefix("-acme"), "");
        assert_eq!(principal_prefix(""), "");
    }

    // ---- Serialised shape ----

    #[test]
    fn managed_by_serialises_as_a_tagged_object() {
        let mark = ManagedBy::Automation {
            environment: "pr-42".to_string(),
        };
        let json = serde_json::to_string(&mark).expect("serialises");
        assert_eq!(json, r#"{"kind":"automation","environment":"pr-42"}"#);
        let back: ManagedBy = serde_json::from_str(&json).expect("round trips");
        assert_eq!(back, mark);
        assert!(
            serde_json::from_str::<ManagedBy>(
                r#"{"kind":"automation","environment":"x","extra":1}"#
            )
            .is_err(),
            "an unknown field is a shape change, not noise"
        );
    }

    #[test]
    fn certificate_mode_serialises_as_mode_and_optional_id() {
        assert_eq!(
            serde_json::to_string(&CertificateMode::Auto).expect("serialises"),
            r#"{"mode":"auto"}"#
        );
        assert_eq!(
            serde_json::to_string(&CertificateMode::Explicit("cert-1".to_string()))
                .expect("serialises"),
            r#"{"mode":"explicit","certificate_id":"cert-1"}"#
        );
    }
}
