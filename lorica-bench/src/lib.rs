#![deny(clippy::all)]
#![deny(unsafe_code)]

pub mod active_probes;
pub mod load_test;
pub mod metrics;
pub mod passive_sla;
pub mod results;
pub mod scheduler;

pub use active_probes::ProbeScheduler;
pub use load_test::LoadTestEngine;
pub use passive_sla::SlaCollector;

/// `route_id` as an operator names the route
/// ([`lorica_config::models::Route::display_name`]), or the id itself when
/// the store no longer holds it: an alert about a route deleted meanwhile
/// still says which one.
pub(crate) fn route_display_name(store: &lorica_config::ConfigStore, route_id: &str) -> String {
    match store.get_route(route_id) {
        Ok(Some(route)) => route.display_name(),
        Ok(None) | Err(_) => route_id.to_string(),
    }
}
