//! Route CRUD HTTP handlers and per-feature validators.
//!
//! **Validation split:** this module performs *type-shape* validation
//! (enum parsing, range checks, field format like `host:port`, regex
//! compilability) on the request body before handing off to the store
//! layer. *Business-rule* validation (hostname uniqueness across routes,
//! cross-field invariants that require the full DB view, encryption of
//! sensitive fields) lives in `lorica-config::store`. The split keeps
//! the API layer free of storage concerns and lets the store stay the
//! single source of truth for rules that depend on existing rows.
//!
//! **Layout.** Types, handlers, and validators are grouped by feature:
//!
//! - [`crud`] - the five CRUD handlers (`list_routes`, `get_route`,
//!   `create_route`, `update_route`, `delete_route`), the
//!   `RouteResponse` / `CreateRouteRequest` / `UpdateRouteRequest`
//!   wrappers, and the `route_to_response` view builder.
//! - [`path_rules`] - per-path rule request/response types and
//!   `build_path_rules` validator.
//! - [`header_rules`] - header-based routing rule type and
//!   `build_header_rule` validator.
//! - [`traffic_splits`] - canary traffic split type, per-entry
//!   validator, and cumulative-weight checker.
//! - [`forward_auth`] - forward-auth config type, validator, and the
//!   `POST /api/v1/validate/forward-auth` endpoint.
//! - [`mirror`] - request mirroring config type and validator.
//! - [`response_rewrite`] - response body rewrite config type and
//!   validator.
//! - [`mtls`] - per-route mTLS config type, validator, and the
//!   `POST /api/v1/validate/mtls-pem` endpoint.

pub mod cert_export;
pub mod crud;
pub mod forward_auth;
pub mod header_rules;
pub mod mirror;
pub mod mtls;
pub mod path_rules;
pub mod response_rewrite;
pub mod traffic_splits;

// Re-export the items mounted on the axum router (server.rs binds them
// as `crate::routes::<name>`) and the public request/response types so
// external code can still name `lorica_api::routes::RouteResponse` etc.
pub use crud::{
    create_route, delete_route, get_route, list_routes, update_route, CreateRouteRequest,
    RouteResponse, UpdateRouteRequest,
};
pub use forward_auth::{
    validate_forward_auth, ForwardAuthConfigRequest, ValidateForwardAuthRequest,
    ValidateForwardAuthResponse,
};
pub use header_rules::HeaderRuleRequest;
pub use mirror::MirrorConfigRequest;
pub use mtls::{
    validate_mtls_pem, MtlsConfigRequest, ValidateMtlsPemRequest, ValidateMtlsPemResponse,
};
pub use path_rules::{PathRuleRequest, PathRuleResponse};
pub use response_rewrite::{ResponseRewriteConfigRequest, ResponseRewriteRuleRequest};
pub use traffic_splits::TrafficSplitRequest;
