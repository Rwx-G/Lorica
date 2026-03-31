use axum::extract::Extension;
use axum::Json;
use serde::Serialize;
use sysinfo::{Pid, System};

use crate::error::{json_data, ApiError};
use crate::server::AppState;

#[derive(Serialize)]
pub struct SystemResponse {
    pub host: HostMetrics,
    pub process: ProcessMetrics,
    pub proxy: ProxyInfo,
}

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
    /// Total disk space in bytes (root mount).
    pub disk_total_bytes: u64,
    /// Used disk space in bytes.
    pub disk_used_bytes: u64,
    /// Disk usage percentage (0-100).
    pub disk_usage_percent: f64,
}

#[derive(Serialize)]
pub struct ProcessMetrics {
    /// Lorica process memory usage in bytes (RSS).
    pub memory_bytes: u64,
    /// Lorica process CPU usage percentage.
    pub cpu_usage_percent: f32,
}

#[derive(Serialize)]
pub struct ProxyInfo {
    /// Lorica version string.
    pub version: String,
    /// Uptime in seconds since the process started.
    pub uptime_seconds: u64,
    /// Number of active proxy connections (from config backends).
    pub active_connections: u64,
}

/// Cached system info to avoid expensive re-creation on every request.
pub struct SystemCache {
    sys: System,
}

impl SystemCache {
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

/// GET /api/v1/system
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

    // Disk (aggregate all disks)
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let (disk_total, disk_available) = disks.iter().fold((0u64, 0u64), |(total, avail), d| {
        (total + d.total_space(), avail + d.available_space())
    });
    let disk_used = disk_total.saturating_sub(disk_available);
    let disk_percent = if disk_total > 0 {
        (disk_used as f64 / disk_total as f64) * 100.0
    } else {
        0.0
    };

    // Process metrics
    let pid = Pid::from_u32(std::process::id());
    let (proc_mem, proc_cpu) = sys
        .process(pid)
        .map(|p| (p.memory(), p.cpu_usage()))
        .unwrap_or((0, 0.0));

    // Proxy info
    let uptime = state.started_at.elapsed().as_secs();
    let active_connections = state
        .active_connections
        .load(std::sync::atomic::Ordering::Relaxed);

    let response = SystemResponse {
        host: HostMetrics {
            cpu_usage_percent: cpu_usage,
            cpu_count,
            memory_total_bytes: mem_total,
            memory_used_bytes: mem_used,
            memory_usage_percent: (mem_percent * 10.0).round() / 10.0,
            disk_total_bytes: disk_total,
            disk_used_bytes: disk_used,
            disk_usage_percent: (disk_percent * 10.0).round() / 10.0,
        },
        process: ProcessMetrics {
            memory_bytes: proc_mem,
            cpu_usage_percent: proc_cpu,
        },
        proxy: ProxyInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: uptime,
            active_connections,
        },
    };

    Ok(json_data(response))
}
