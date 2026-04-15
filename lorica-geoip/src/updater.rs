// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Auto-update job for the DB-IP Lite Country database.
//!
//! The supervisor runs [`spawn_updater`] once at startup when
//! `GlobalSettings.geoip_auto_update_enabled` is true. The task loops
//! forever: on each tick it computes the current `YYYY-MM` tag (UTC),
//! downloads the matching `.mmdb.gz`, decompresses to a temp file,
//! validates via [`GeoIpResolver::load_from_path`]'s sanity check,
//! atomic-renames onto the operator-configured path, and calls
//! `resolver.load_from_path(...)` so the in-memory reader is
//! replaced without dropping in-flight requests. Interval defaults
//! to 7 days; on any failure the loop serves the old DB (which may
//! be the one on disk from a previous tick or a MaxMind-licensed
//! copy the operator installed manually) and retries on the next
//! tick rather than hammering the upstream.
//!
//! **Attribution (CC-BY 4.0).** DB-IP.com publishes the Lite Country
//! database under Creative Commons Attribution 4.0
//! (<https://creativecommons.org/licenses/by/4.0/>). The Lorica
//! project fulfills the attribution requirement in `NOTICE` and in
//! the `docs/` pages that surface the feature; no per-response
//! attribution is injected into user traffic.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{Datelike, Utc};
use flate2::read::GzDecoder;
use std::io::Read;
use thiserror::Error;

use crate::{GeoIpError, GeoIpResolver};

/// How often the auto-update task ticks. The DB-IP Lite feed is
/// refreshed monthly, but a 24-hour cadence keeps Lorica within one
/// day of any mid-month regeneration (happens when the upstream
/// maintainer ships a fix or the geolocation dataset is re-scored),
/// and matches the cadence operators expect from other IP-reputation
/// feeds. Bandwidth cost stays trivial: the gzip is ~3 MiB so one
/// download per day is a rounding error on any internet link, and
/// the atomic ArcSwap publish means in-flight requests are never
/// blocked.
pub const UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Conservative floor for the uncompressed `.mmdb` size. The DB-IP
/// Lite Country feed ships ~3 MiB uncompressed; anything smaller
/// than 1 MiB is either truncated or the wrong artefact.
const MIN_MMDB_SIZE: u64 = 1024 * 1024;

/// Upper bound on the uncompressed download. A runaway response
/// (redirect loop into a huge blob, accidentally served something
/// other than the country DB) cannot exhaust disk or memory.
const MAX_MMDB_SIZE: u64 = 128 * 1024 * 1024;

/// Upper bound on the compressed download. Uncompressed is capped
/// above; this guards against a malicious zip bomb before we start
/// decompressing.
const MAX_GZIP_SIZE: u64 = 32 * 1024 * 1024;

/// How long to wait for the HTTP GET + full body. The DB is small
/// (~3 MiB compressed) but DB-IP's CDN is occasionally slow; 2 min
/// is generous without letting a hung proxy pin the task.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// Default download URL template. `{tag}` is replaced with the
/// UTC `YYYY-MM` tag at request time. Overridable via
/// [`UpdaterConfig::url_template`] so operators behind a mirror
/// or with a MaxMind licensed feed can swap the source without
/// forking.
pub const DEFAULT_URL_TEMPLATE: &str =
    "https://download.db-ip.com/free/dbip-country-lite-{tag}.mmdb.gz";

/// Typed errors for the auto-update path. Callers can distinguish
/// a transient network blip from a persistent validation failure so
/// metrics / alerts can fire on the persistent case only.
#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("download failed: {0}")]
    Download(String),
    #[error("response too large: got {got} bytes, cap {cap}")]
    TooLarge { got: u64, cap: u64 },
    #[error("response too small: got {got} bytes, min {min}")]
    TooSmall { got: u64, min: u64 },
    #[error("gzip decode failed: {0}")]
    Decompress(String),
    #[error("validation failed: {0}")]
    Validation(#[from] GeoIpError),
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
}

/// Runtime configuration for the auto-update task. Most operators
/// only set `target_path`; the rest have sensible defaults.
#[derive(Debug, Clone)]
pub struct UpdaterConfig {
    /// Filesystem path where the live `.mmdb` is kept. Typically
    /// matches `GlobalSettings.geoip_db_path`. Must be writable by
    /// the supervisor user. Parent directory is created on first run.
    pub target_path: PathBuf,
    /// URL template with `{tag}` placeholder. Defaults to the
    /// DB-IP Lite Country feed.
    pub url_template: String,
    /// Poll interval between download attempts. Defaults to 7 days.
    /// Lower values only make sense for testing.
    pub interval: Duration,
}

impl UpdaterConfig {
    pub fn new(target_path: impl Into<PathBuf>) -> Self {
        Self {
            target_path: target_path.into(),
            url_template: DEFAULT_URL_TEMPLATE.to_string(),
            interval: UPDATE_INTERVAL,
        }
    }
}

/// Compute the `YYYY-MM` tag for today (UTC). Used to interpolate
/// the download URL. Exposed for tests.
pub fn current_month_tag(now: chrono::DateTime<Utc>) -> String {
    format!("{:04}-{:02}", now.year(), now.month())
}

/// Build the concrete download URL for the current month. `{tag}`
/// in `template` is replaced with the `YYYY-MM` tag in UTC so a
/// proxy crossing midnight UTC picks up the new month's file on
/// the next tick.
fn build_download_url(template: &str, now: chrono::DateTime<Utc>) -> String {
    template.replace("{tag}", &current_month_tag(now))
}

/// Run one download + validate + install cycle. Usually called from
/// [`spawn_updater`]; exposed publicly for the config-reload path
/// so an operator who just turned auto-update on can force an
/// immediate refresh without waiting 7 days.
///
/// On success, `resolver` now points at the freshly downloaded DB
/// and `cfg.target_path` on disk holds the validated payload.
///
/// On any failure, the previously-loaded DB (if any) stays in
/// `resolver`; the target_path on disk is not touched (partial
/// downloads land in a temp file that is removed on failure).
pub async fn run_once(
    resolver: &GeoIpResolver,
    cfg: &UpdaterConfig,
) -> Result<(), UpdateError> {
    let url = build_download_url(&cfg.url_template, Utc::now());

    tracing::info!(url = %url, "geoip updater: downloading database");

    // 1. Ensure parent dir exists. `create_dir_all` is idempotent
    //    and treats "already exists" as success.
    if let Some(parent) = cfg.target_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // 2. HTTP GET with a strict timeout so a hung proxy cannot wedge
    //    the task forever. reqwest's default client is fine; we only
    //    need one download per 7 days so a fresh Client each call is
    //    cheaper than holding one open.
    let client = reqwest::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT)
        .user_agent(format!(
            "lorica/{} (+github.com/Rwx-G/Lorica)",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .map_err(|e| UpdateError::Download(format!("client build: {e}")))?;

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| UpdateError::Download(format!("GET {url}: {e}")))?;

    if !resp.status().is_success() {
        return Err(UpdateError::Download(format!(
            "GET {url}: HTTP {}",
            resp.status()
        )));
    }

    // Early size check before allocating: trust the Content-Length
    // hint only as an upper bound filter. If the server lies or
    // omits it we fall back to the streaming cap below.
    if let Some(len) = resp.content_length() {
        if len > MAX_GZIP_SIZE {
            return Err(UpdateError::TooLarge {
                got: len,
                cap: MAX_GZIP_SIZE,
            });
        }
    }

    let gz_bytes = resp
        .bytes()
        .await
        .map_err(|e| UpdateError::Download(format!("read body: {e}")))?;
    if gz_bytes.len() as u64 > MAX_GZIP_SIZE {
        return Err(UpdateError::TooLarge {
            got: gz_bytes.len() as u64,
            cap: MAX_GZIP_SIZE,
        });
    }

    // 3. Decompress in memory with a hard cap so a zip bomb cannot
    //    blow the supervisor's heap. `Read::take(MAX_MMDB_SIZE + 1)`
    //    caps the *output* of the gz decoder; the `+ 1` lets us
    //    detect overflow by checking if we hit the cap exactly.
    let mut decoder = GzDecoder::new(&gz_bytes[..]);
    let mut mmdb_bytes: Vec<u8> = Vec::with_capacity(4 * 1024 * 1024);
    std::io::copy(
        &mut Read::take(&mut decoder, MAX_MMDB_SIZE + 1),
        &mut mmdb_bytes,
    )
    .map_err(|e| UpdateError::Decompress(e.to_string()))?;

    if mmdb_bytes.len() as u64 > MAX_MMDB_SIZE {
        return Err(UpdateError::TooLarge {
            got: mmdb_bytes.len() as u64,
            cap: MAX_MMDB_SIZE,
        });
    }
    if (mmdb_bytes.len() as u64) < MIN_MMDB_SIZE {
        return Err(UpdateError::TooSmall {
            got: mmdb_bytes.len() as u64,
            min: MIN_MMDB_SIZE,
        });
    }

    // 4. Write to a sibling temp file then atomic rename onto the
    //    target. `tempfile` would be simpler but we deliberately
    //    place the temp alongside the target so `rename` is a
    //    same-filesystem operation (atomic by POSIX guarantee).
    let parent = cfg
        .target_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let basename = cfg
        .target_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "lorica.mmdb".to_string());
    let tmp_path = parent.join(format!(".{basename}.tmp"));

    tokio::fs::write(&tmp_path, &mmdb_bytes).await?;

    // 5. Validate via the resolver's own sanity check. If validation
    //    passes, the temp file holds a good DB; if it fails we drop
    //    the temp file and keep serving the old DB.
    //    `load_from_path` also does the atomic ArcSwap, so after this
    //    returns Ok the resolver is already serving the new DB from
    //    the in-memory copy — the rename below is purely for restart
    //    persistence.
    if let Err(e) = resolver.load_from_path(&tmp_path) {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(UpdateError::Validation(e));
    }

    // 6. Move the validated file onto the operator-configured path
    //    so next startup reloads the same DB without re-downloading.
    //    Rename on POSIX is atomic within a filesystem so a
    //    concurrent reader either sees the old or new inode, never
    //    a partial file.
    tokio::fs::rename(&tmp_path, &cfg.target_path).await?;

    tracing::info!(
        target = %cfg.target_path.display(),
        bytes = mmdb_bytes.len(),
        "geoip updater: database refreshed"
    );

    Ok(())
}

/// Spawn the long-running update task. Returns a
/// [`tokio::task::JoinHandle`] the caller holds in a shutdown tracker
/// so a clean SIGTERM aborts the task. The task runs the first cycle
/// immediately (useful on fresh installs: the operator turns
/// auto-update on and gets a DB within minutes instead of waiting
/// 7 days), then ticks every `cfg.interval`.
pub fn spawn_updater(
    resolver: Arc<GeoIpResolver>,
    cfg: UpdaterConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match run_once(&resolver, &cfg).await {
                Ok(()) => {
                    tracing::info!(
                        next_in_s = cfg.interval.as_secs(),
                        "geoip updater: success, sleeping until next tick"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        next_in_s = cfg.interval.as_secs(),
                        "geoip updater: cycle failed, serving previous DB; will retry on next tick"
                    );
                }
            }
            tokio::time::sleep(cfg.interval).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn month_tag_is_zero_padded() {
        let jan = chrono::DateTime::<Utc>::from_naive_utc_and_offset(
            chrono::NaiveDate::from_ymd_opt(2026, 1, 15)
                .unwrap()
                .and_hms_opt(12, 0, 0)
                .unwrap(),
            Utc,
        );
        assert_eq!(current_month_tag(jan), "2026-01");

        let dec = chrono::DateTime::<Utc>::from_naive_utc_and_offset(
            chrono::NaiveDate::from_ymd_opt(2026, 12, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
            Utc,
        );
        assert_eq!(current_month_tag(dec), "2026-12");
    }

    #[test]
    fn build_download_url_substitutes_tag() {
        let now = chrono::DateTime::<Utc>::from_naive_utc_and_offset(
            chrono::NaiveDate::from_ymd_opt(2026, 4, 14)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
            Utc,
        );
        let url = build_download_url(DEFAULT_URL_TEMPLATE, now);
        assert_eq!(
            url,
            "https://download.db-ip.com/free/dbip-country-lite-2026-04.mmdb.gz"
        );
    }

    #[test]
    fn build_download_url_works_with_custom_template() {
        let now = chrono::DateTime::<Utc>::from_naive_utc_and_offset(
            chrono::NaiveDate::from_ymd_opt(2026, 4, 14)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
            Utc,
        );
        let url = build_download_url("https://mirror.example/geoip-{tag}.gz", now);
        assert_eq!(url, "https://mirror.example/geoip-2026-04.gz");
    }

    #[test]
    fn updater_config_defaults_sensibly() {
        let cfg = UpdaterConfig::new("/var/lib/lorica/geoip.mmdb");
        assert_eq!(cfg.target_path.to_str(), Some("/var/lib/lorica/geoip.mmdb"));
        assert_eq!(cfg.interval, UPDATE_INTERVAL);
        assert!(cfg.url_template.contains("{tag}"));
    }

    // -- HTTP integration tests -----------------------------------
    //
    // Spin up a minimal HTTP/1.1 server on 127.0.0.1 in a dedicated
    // std thread (blocking TcpListener is simpler than wiring a
    // tokio server here, since `run_once` already drives a tokio
    // runtime via reqwest). The server serves exactly one canned
    // response then shuts down. These cover story 2.3's error paths
    // without relying on the DB-IP CDN being reachable (the CI
    // sandbox blocks outbound DNS).

    // `std::io::Read` is already in module scope (see the gzip
    // decoder path above); only Write is tests-local.
    use std::io::Write as _;
    use std::net::TcpListener;

    fn spawn_mock_server(
        response: Vec<u8>,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("test setup: bind mock HTTP");
        let addr = listener.local_addr().expect("test setup: local_addr");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(_) => return,
            };
            // Drain the request headers so reqwest's buffered writer
            // does not see a RST before the response lands.
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(&response);
            let _ = stream.flush();
        });
        (format!("http://{addr}"), handle)
    }

    fn http_response(status_line: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn gzip_of(bytes: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    fn test_cfg(base_url: &str) -> UpdaterConfig {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        // NamedTempFile drop would unlink the path; convert to a
        // persistent path the updater can rename onto.
        let _ = tmp.close();
        UpdaterConfig {
            target_path: path,
            url_template: format!("{base_url}/dbip-{{tag}}.mmdb.gz"),
            interval: Duration::from_secs(3600),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_once_returns_download_error_on_http_404() {
        let (base, _h) = spawn_mock_server(http_response("404 Not Found", b"nope"));
        let cfg = test_cfg(&base);
        let resolver = GeoIpResolver::empty();
        let err = run_once(&resolver, &cfg).await.unwrap_err();
        match err {
            UpdateError::Download(msg) => {
                assert!(msg.contains("404"), "msg={msg}");
            }
            other => panic!("expected Download error on 404, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_once_rejects_small_gzip_as_too_small() {
        // Valid gzip payload but the uncompressed bytes sit well under
        // MIN_MMDB_SIZE. Boundary-enforcement check for the size
        // floor; without it a truncated upstream would silently
        // install a broken DB.
        let tiny = gzip_of(b"not-really-an-mmdb");
        let (base, _h) = spawn_mock_server(http_response("200 OK", &tiny));
        let cfg = test_cfg(&base);
        let resolver = GeoIpResolver::empty();
        let err = run_once(&resolver, &cfg).await.unwrap_err();
        match err {
            UpdateError::TooSmall { got, min } => {
                assert!(got < min, "got={got} min={min}");
                assert_eq!(min, MIN_MMDB_SIZE);
            }
            other => panic!("expected TooSmall, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_once_rejects_garbage_as_validation_error() {
        // 2 MiB of zeros gzips extremely well (down to ~2 KiB), so
        // the server-side payload stays tiny, but after decompression
        // we clear MIN_MMDB_SIZE and the maxminddb reader rejects it
        // at validation. Exercises the `Validation` variant of
        // UpdateError which is the last line of defense.
        let payload = vec![0u8; 2 * 1024 * 1024];
        let gz = gzip_of(&payload);
        let (base, _h) = spawn_mock_server(http_response("200 OK", &gz));
        let cfg = test_cfg(&base);
        let resolver = GeoIpResolver::empty();
        let err = run_once(&resolver, &cfg).await.unwrap_err();
        match err {
            UpdateError::Validation(_) => { /* expected */ }
            other => panic!("expected Validation, got {other:?}"),
        }
        // The target_path must NOT have been created - the temp
        // file got removed and the rename never fired.
        assert!(
            !cfg.target_path.exists(),
            "target_path leaked on validation failure"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_once_rejects_oversized_compressed_body() {
        // Serve MAX_GZIP_SIZE + 1024 bytes. The early content-length
        // check fires first; this confirms the gzip-side cap is wired
        // and we do not allocate the full download into memory.
        let big = vec![0u8; (MAX_GZIP_SIZE + 1024) as usize];
        let (base, _h) = spawn_mock_server(http_response("200 OK", &big));
        let cfg = test_cfg(&base);
        let resolver = GeoIpResolver::empty();
        let err = run_once(&resolver, &cfg).await.unwrap_err();
        match err {
            UpdateError::TooLarge { got, cap } => {
                assert!(got > cap, "got={got} cap={cap}");
                assert_eq!(cap, MAX_GZIP_SIZE);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }
}
