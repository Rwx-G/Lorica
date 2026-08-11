//! Server-side password policy (Story 8.3 AC #8).
//!
//! Single authoritative validator applied wherever a password is SET:
//! the change-password flow and the users CRUD. Login verification
//! never runs the policy (existing hashes stay valid across policy
//! tightening). The frontend mirrors the same rules for UX only.

use lorica_config::models::GlobalSettings;

use crate::error::ApiError;

/// Hard upper bound on password length, independent of settings.
/// Guards the Argon2 hasher against DoS-sized inputs.
const PASSWORD_MAX_LENGTH: usize = 128;

/// Validate a candidate password against the configured policy
/// (`password_min_length`, `password_require_complexity`). Returns
/// `ApiError::BadRequest` with an operator-readable reason on the
/// first rule violated.
pub fn validate_password(password: &str, settings: &GlobalSettings) -> Result<(), ApiError> {
    let min_length = settings.password_min_length as usize;
    if password.chars().count() < min_length {
        return Err(ApiError::BadRequest(format!(
            "password must be at least {min_length} characters"
        )));
    }
    if password.len() > PASSWORD_MAX_LENGTH {
        return Err(ApiError::BadRequest(format!(
            "password must not exceed {PASSWORD_MAX_LENGTH} characters"
        )));
    }
    if settings.password_require_complexity {
        let has_upper = password.chars().any(|c| c.is_uppercase());
        let has_lower = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        // "Symbol" = anything that is not alphanumeric, whitespace
        // included on purpose: passphrases with spaces satisfy the
        // class without forcing punctuation.
        let has_symbol = password.chars().any(|c| !c.is_alphanumeric());
        if !(has_upper && has_lower && has_digit && has_symbol) {
            return Err(ApiError::BadRequest(
                "password must contain at least one uppercase letter, one lowercase letter, \
                 one digit, and one symbol"
                    .into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(min: u32, complexity: bool) -> GlobalSettings {
        GlobalSettings {
            password_min_length: min,
            password_require_complexity: complexity,
            ..GlobalSettings::default()
        }
    }

    #[test]
    fn rejects_below_min_length() {
        let err = validate_password("Short1!", &settings(14, true)).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(msg) if msg.contains("at least 14")));
    }

    #[test]
    fn rejects_over_max_length() {
        let long = format!("Aa1!{}", "x".repeat(130));
        let err = validate_password(&long, &settings(14, true)).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(msg) if msg.contains("128")));
    }

    #[test]
    fn rejects_missing_character_classes() {
        // Long enough but no digit and no symbol.
        let err = validate_password("OnlyLettersHereAbc", &settings(14, true)).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(msg) if msg.contains("uppercase")));
    }

    #[test]
    fn accepts_compliant_password() {
        assert!(validate_password("Correct-Horse-42!", &settings(14, true)).is_ok());
    }

    #[test]
    fn space_counts_as_symbol() {
        assert!(validate_password("Correct Horse 42x", &settings(14, true)).is_ok());
    }

    #[test]
    fn complexity_off_only_checks_length() {
        assert!(validate_password("aaaaaaaaaaaaaa", &settings(14, false)).is_ok());
        assert!(validate_password("aaaa", &settings(14, false)).is_err());
    }

    #[test]
    fn min_length_counts_chars_not_bytes() {
        // 14 chars with a multibyte uppercase: passes a char-based
        // minimum even though the byte length differs.
        assert!(validate_password("Éaaaaaaaaaa42!", &settings(14, true)).is_ok());
    }
}
