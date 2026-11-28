//! Khaymali Light — stamped-UDP TUN data plane (integrated).

mod config;
mod frame;
mod tun;
mod link;
mod service;

pub use config::KmLightConfig;
pub use link::Link;
pub use service::{gen_secret, install_service, save_config, service_restart, service_status, service_stop};
