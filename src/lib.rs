pub mod app;
pub mod config;
pub mod connections;
pub mod elevation;
pub mod engine;
pub mod events;
pub mod firewall;
pub mod language;
pub mod logging;
pub mod monitor;
pub mod monitor_runtime;
pub mod monitor_ui;
pub mod policy;
pub mod service;
pub mod state;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
