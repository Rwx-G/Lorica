//! Host, process, and proxy resource metrics surfaced via `/api/v1/system`.

use axum::extract::Extension;
use axum::Json;
use serde::Serialize;
use sysinfo::{Pid, System};

use crate::error::{json_data, ApiError};
use crate::server::AppState;

/// Top-level payload returned by `GET /api/v1/system`.
#[derive(Serialize)]
pub struct SystemResponse {
    pub host: HostMetrics,
    pub process: ProcessMetrics,
    pub proxy: ProxyInfo,
}

/// Host-level CPU, memory, and disk usage.
#[derive(Serialize)]
pub struct HostMetrics {
    /// Total CPU usage percentage (0-100).
    pub cpu_usage_percent: f32,
    /// Number of CPU cores.
    pub cpu_count: usize,
    /// Total physical memory in bytes.
    pub memory_total_bytes: u64,
    /// Used physical memory in bytes.
    pub memory_used_bytes: u64,
    /// Memory usage percentage (0-100).
    pub memory_usage_percent: f64,
    /// Root filesystem (`/`). Null if the mount cannot be read.
    pub disk_root: Option<DiskUsage>,
    /// Filesystem that holds the Lorica data-dir (typically
    /// `/var/lib/lorica`). Picked as the mount entry with the
    /// longest path prefix that `data_dir` starts with. Null if
    /// resolution fails. On a typical single-disk host this is the
    /// same filesystem as `disk_root`; the frontend surfaces both
    /// so an operator whose data-dir lives on a dedicated volume
    /// sees the relevant one at a glance.
    pub disk_data: Option<DiskUsage>,
}

/// One filesystem's usage snapshot. Used for both the root mount
/// and the data-dir mount.
#[derive(Serialize)]
pub struct DiskUsage {
    /// Absolute path of the mount point (e.g. `/` or `/var/lib`).
    pub mount_point: String,
    /// Total bytes available to users on this filesystem.
    pub total_bytes: u64,
    /// Bytes currently in use (total - available).
    pub used_bytes: u64,
    /// Usage percentage (0-100).
    pub usage_percent: f64,
}

/// Lorica process resource usage.
#[derive(Serialize)]
pub struct ProcessMetrics {
    /// Lorica process memory usage in bytes (RSS).
    pub memory_bytes: u64,
    /// Lorica process CPU usage percentage.
    pub cpu_usage_percent: f32,
}

/// Proxy version, uptime, listen ports, and live connection count.
#[derive(Serialize)]
pub struct ProxyInfo {
    /// Lorica version string.
    pub version: String,
    /// Uptime in seconds since the process started.
    pub uptime_seconds: u64,
    /// Number of active proxy connections (from config backends).
    pub active_connections: u64,
    /// HTTP proxy listen port.
    pub http_port: u16,
    /// HTTPS proxy listen port.
    pub https_port: u16,
}

/// Cached `sysinfo::System` instance, kept in `AppState` to avoid the cost of
/// recreating it on every request.
pub struct SystemCache {
    sys: System,
}

impl Default for SystemCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemCache {
    /// Initialize the cache and perform a full first refresh.
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        Self { sys }
    }

    /// Get CPU usage percentage after refresh.
    pub fn cpu_usage_percent(&self) -> f32 {
        self.sys.global_cpu_usage()
    }

    /// Get used memory in bytes after refresh.
    pub fn memory_used_bytes(&self) -> u64 {
        self.sys.used_memory()
    }

    /// Refresh only the metrics we need (CPU, memory, process).
    pub fn refresh(&mut self) {
        self.sys.refresh_cpu_all();
        self.sys.refresh_memory();
        self.sys.refresh_processes(
            sysinfo::ProcessesToUpdate::Some(&[Pid::from_u32(std::process::id())]),
            true,
        );
    }
}

/// GET /api/v1/system - return host, process, and proxy resource usage.
pub async fn get_system(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut sys_cache = state.system_cache.lock().await;
    sys_cache.refresh();
    let sys = &sys_cache.sys;

    // Host CPU
    let cpu_usage = sys.global_cpu_usage();
    let cpu_count = sys.cpus().len();

    // Host memory
    let mem_total = sys.total_memory();
    let mem_used = sys.used_memory();
    let mem_percent = if mem_total > 0 {
        (mem_used as f64 / mem_total as f64) * 100.0
    } else {
        0.0
    };

    // Disk: two distinct entries, root (`/`) and the mount holding
    // the Lorica data-dir. We call statvfs(2) directly on each path
    // rather than summing `Disks::new_with_refreshed_list()`, for
    // two reasons: sysinfo's list-based aggregation double-counts
    // tmpfs / bind mounts / overlayfs, and sysinfo's
    // `available_space()` excludes reserved root blocks - which
    // inflates the computed "used" by the reserved pool (~5 % of
    // total on ext4 default). statvfs gives us the same numbers as
    // `df -h`.
    let disk_root = disk_usage_statvfs(std::path::Path::new("/"));
    let disk_data = disk_usage_statvfs(&state.data_dir);

    // Process metrics
    let pid = Pid::from_u32(std::process::id());
    let (proc_mem, proc_cpu) = sys
        .process(pid)
        .map(|p| (p.memory(), p.cpu_usage()))
        .unwrap_or((0, 0.0));

    // Proxy info
    let uptime = state.started_at.elapsed().as_secs();
    let mut active_connections = state
        .active_connections
        .load(std::sync::atomic::Ordering::Relaxed);
    // In supervisor mode, the local counter is 0; read from aggregated workers
    if active_connections == 0 {
        if let Some(ref agg) = state.aggregated_metrics {
            active_connections = agg.total_active_connections().await;
        }
    }

    let response = SystemResponse {
        host: HostMetrics {
            cpu_usage_percent: cpu_usage,
            cpu_count,
            memory_total_bytes: mem_total,
            memory_used_bytes: mem_used,
            memory_usage_percent: (mem_percent * 10.0).round() / 10.0,
            disk_root,
            disk_data,
        },
        process: ProcessMetrics {
            memory_bytes: proc_mem,
            cpu_usage_percent: proc_cpu,
        },
        proxy: ProxyInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: uptime,
            active_connections,
            http_port: state.http_port,
            https_port: state.https_port,
        },
    };

    Ok(json_data(response))
}

/// Run `statvfs(path)` and translate the result into a `DiskUsage`
/// that matches `df -h`'s columns:
///
/// - `total_bytes` = (f_blocks - reserved) * f_frsize, the capacity
///   visible to a non-root user. Matches df's "Size" column.
/// - `used_bytes`  = (f_blocks - f_bfree) * f_frsize, matches df's
///   "Used" column (the bytes currently written to the filesystem,
///   independent of the reserved-for-root pool).
/// - `usage_percent` = used / (used + avail), matches df's "Use%"
///   column exactly.
///
/// Returns `None` if the path does not exist, is on a filesystem
/// that does not support statvfs, or the call fails.
fn disk_usage_statvfs(path: &std::path::Path) -> Option<DiskUsage> {
    let stat = nix::sys::statvfs::statvfs(path).ok()?;

    let frsize = stat.fragment_size();
    let blocks = stat.blocks();
    let free = stat.blocks_free();
    let avail = stat.blocks_available();
    let reserved = free.saturating_sub(avail);
    let used_blocks = blocks.saturating_sub(free);
    let visible_blocks = blocks.saturating_sub(reserved);

    let total_bytes = visible_blocks * frsize;
    let used_bytes = used_blocks * frsize;
    let avail_bytes = avail * frsize;
    let denom = used_bytes + avail_bytes;
    let percent = if denom > 0 {
        (used_bytes as f64 / denom as f64) * 100.0
    } else {
        0.0
    };

    Some(DiskUsage {
        mount_point: path.to_string_lossy().into_owned(),
        total_bytes,
        used_bytes,
        usage_percent: (percent * 10.0).round() / 10.0,
    })
}
