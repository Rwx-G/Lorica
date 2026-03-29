# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Project documentation: brief, PRD (5 epics, 25 stories), architecture (sharded), brainstorming results
- Initial repository setup with LICENSE, README, CHANGELOG
- **Story 1.1:** Fork Pingora v0.8.0 and rename to Lorica (17 crates, 178 .rs files)
- NOTICE file with Cloudflare Pingora attribution (Apache-2.0)

### Changed

- All crates renamed from `pingora-*` to `lorica-*`
- TLS standardized on rustls only (openssl, boringssl, s2n features removed)
- `serde_yaml` replaced with `serde_yml`
- All crate versions set to 0.1.0

### Removed

- Pingora examples and tests from facade crate
- Sentry integration features
- OpenSSL, BoringSSL, s2n-tls backend crates (not copied)
