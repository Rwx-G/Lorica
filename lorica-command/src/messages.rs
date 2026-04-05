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

//! Protobuf message types for the command channel protocol.
//!
//! Defined using prost derive macros to avoid requiring protoc at build time.
//! See `proto/command.proto` for the canonical schema documentation.

use std::time::{SystemTime, UNIX_EPOCH};

/// Command types sent from supervisor to worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum CommandType {
    Unspecified = 0,
    ConfigReload = 1,
    Heartbeat = 2,
    Shutdown = 3,
    MetricsRequest = 4,
}

impl CommandType {
    pub fn from_i32(v: i32) -> Self {
        match v {
            1 => Self::ConfigReload,
            2 => Self::Heartbeat,
            3 => Self::Shutdown,
            4 => Self::MetricsRequest,
            _ => Self::Unspecified,
        }
    }
}

/// Response status codes from worker to supervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum ResponseStatus {
    Unspecified = 0,
    Ok = 1,
    Error = 2,
    Processing = 3,
}

impl ResponseStatus {
    pub fn from_i32(v: i32) -> Self {
        match v {
            1 => Self::Ok,
            2 => Self::Error,
            3 => Self::Processing,
            _ => Self::Unspecified,
        }
    }
}

/// Command message sent from supervisor to worker.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Command {
    #[prost(int32, tag = "1")]
    pub command_type: i32,
    #[prost(uint64, tag = "2")]
    pub sequence: u64,
    #[prost(uint64, tag = "3")]
    pub timestamp_ms: u64,
}

impl Command {
    /// Create a new command with auto-populated timestamp.
    pub fn new(command_type: CommandType, sequence: u64) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            command_type: command_type as i32,
            sequence,
            timestamp_ms,
        }
    }

    /// Get the typed command type.
    pub fn typed_command(&self) -> CommandType {
        CommandType::from_i32(self.command_type)
    }
}

/// Response message sent from worker to supervisor.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Response {
    #[prost(int32, tag = "1")]
    pub status: i32,
    #[prost(uint64, tag = "2")]
    pub sequence: u64,
    #[prost(string, tag = "3")]
    pub message: ::prost::alloc::string::String,
}

impl Response {
    /// Create an Ok response.
    pub fn ok(sequence: u64) -> Self {
        Self {
            status: ResponseStatus::Ok as i32,
            sequence,
            message: String::new(),
        }
    }

    /// Create an Error response.
    pub fn error(sequence: u64, message: impl Into<String>) -> Self {
        Self {
            status: ResponseStatus::Error as i32,
            sequence,
            message: message.into(),
        }
    }

    /// Create a Processing response.
    pub fn processing(sequence: u64, message: impl Into<String>) -> Self {
        Self {
            status: ResponseStatus::Processing as i32,
            sequence,
            message: message.into(),
        }
    }

    /// Get the typed response status.
    pub fn typed_status(&self) -> ResponseStatus {
        ResponseStatus::from_i32(self.status)
    }
}

/// A single banned IP entry in a metrics report.
#[derive(Clone, PartialEq, prost::Message)]
pub struct BanReportEntry {
    /// Banned IP address.
    #[prost(string, tag = "1")]
    pub ip: String,
    /// Seconds remaining before the ban expires.
    #[prost(uint64, tag = "2")]
    pub remaining_seconds: u64,
    /// Total ban duration in seconds.
    #[prost(uint64, tag = "3")]
    pub ban_duration_seconds: u64,
}

/// A single backend EWMA latency entry in a metrics report.
#[derive(Clone, PartialEq, prost::Message)]
pub struct EwmaReportEntry {
    /// Backend address (e.g. "10.0.0.1:8080").
    #[prost(string, tag = "1")]
    pub backend_address: String,
    /// EWMA latency score in microseconds.
    #[prost(double, tag = "2")]
    pub score_us: f64,
}

/// Metrics data sent from worker to supervisor for aggregation.
///
/// Workers report their metrics on MetricsRequest.
/// The supervisor aggregates them into the global /metrics and API endpoints.
#[derive(Clone, PartialEq, prost::Message)]
pub struct MetricsReport {
    /// Worker ID.
    #[prost(uint32, tag = "1")]
    pub worker_id: u32,
    /// Total requests processed by this worker.
    #[prost(uint64, tag = "2")]
    pub total_requests: u64,
    /// Active connections on this worker.
    #[prost(uint64, tag = "3")]
    pub active_connections: u64,
    /// Timestamp of the report.
    #[prost(uint64, tag = "4")]
    pub timestamp_ms: u64,
    /// Cumulative cache hits.
    #[prost(uint64, tag = "5")]
    pub cache_hits: u64,
    /// Cumulative cache misses.
    #[prost(uint64, tag = "6")]
    pub cache_misses: u64,
    /// Active ban entries (non-expired).
    #[prost(message, repeated, tag = "7")]
    pub ban_entries: Vec<BanReportEntry>,
    /// Per-backend EWMA latency scores.
    #[prost(message, repeated, tag = "8")]
    pub ewma_entries: Vec<EwmaReportEntry>,
}

impl MetricsReport {
    pub fn new(worker_id: u32, total_requests: u64, active_connections: u64) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            worker_id,
            total_requests,
            active_connections,
            timestamp_ms,
            cache_hits: 0,
            cache_misses: 0,
            ban_entries: Vec::new(),
            ewma_entries: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_new() {
        let cmd = Command::new(CommandType::ConfigReload, 42);
        assert_eq!(cmd.typed_command(), CommandType::ConfigReload);
        assert_eq!(cmd.sequence, 42);
        assert!(cmd.timestamp_ms > 0);
    }

    #[test]
    fn test_command_type_roundtrip() {
        for ct in [
            CommandType::Unspecified,
            CommandType::ConfigReload,
            CommandType::Heartbeat,
            CommandType::Shutdown,
        ] {
            assert_eq!(CommandType::from_i32(ct as i32), ct);
        }
    }

    #[test]
    fn test_response_ok() {
        let resp = Response::ok(1);
        assert_eq!(resp.typed_status(), ResponseStatus::Ok);
        assert_eq!(resp.sequence, 1);
        assert!(resp.message.is_empty());
    }

    #[test]
    fn test_response_error() {
        let resp = Response::error(5, "config load failed");
        assert_eq!(resp.typed_status(), ResponseStatus::Error);
        assert_eq!(resp.sequence, 5);
        assert_eq!(resp.message, "config load failed");
    }

    #[test]
    fn test_response_processing() {
        let resp = Response::processing(3, "draining connections");
        assert_eq!(resp.typed_status(), ResponseStatus::Processing);
    }

    #[test]
    fn test_response_status_roundtrip() {
        for rs in [
            ResponseStatus::Unspecified,
            ResponseStatus::Ok,
            ResponseStatus::Error,
            ResponseStatus::Processing,
        ] {
            assert_eq!(ResponseStatus::from_i32(rs as i32), rs);
        }
    }

    #[test]
    fn test_command_prost_encode_decode() {
        use prost::Message;

        let cmd = Command::new(CommandType::Heartbeat, 99);
        let encoded = cmd.encode_to_vec();
        let decoded = Command::decode(&encoded[..]).expect("decode failed");
        assert_eq!(decoded, cmd);
    }

    #[test]
    fn test_metrics_report_prost_encode_decode() {
        use prost::Message;

        let report = MetricsReport {
            worker_id: 1,
            total_requests: 5000,
            active_connections: 42,
            timestamp_ms: 1234567890,
            cache_hits: 3000,
            cache_misses: 2000,
            ban_entries: vec![
                BanReportEntry {
                    ip: "192.168.1.100".into(),
                    remaining_seconds: 300,
                    ban_duration_seconds: 600,
                },
            ],
            ewma_entries: vec![
                EwmaReportEntry {
                    backend_address: "10.0.0.1:8080".into(),
                    score_us: 1500.5,
                },
                EwmaReportEntry {
                    backend_address: "10.0.0.2:8080".into(),
                    score_us: 2300.0,
                },
            ],
        };
        let encoded = report.encode_to_vec();
        let decoded = MetricsReport::decode(&encoded[..]).expect("decode failed");
        assert_eq!(decoded, report);
        assert_eq!(decoded.ban_entries.len(), 1);
        assert_eq!(decoded.ewma_entries.len(), 2);
        assert_eq!(decoded.cache_hits, 3000);
    }

    #[test]
    fn test_response_prost_encode_decode() {
        use prost::Message;

        let resp = Response::error(7, "test error");
        let encoded = resp.encode_to_vec();
        let decoded = Response::decode(&encoded[..]).expect("decode failed");
        assert_eq!(decoded, resp);
    }
}
