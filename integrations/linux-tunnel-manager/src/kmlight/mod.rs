//! Khaymali Light — lightweight stamped-UDP TUN tunnel (pure Rust).

pub mod config;
pub mod frame;
pub mod tun;
pub mod link;

pub use config::KmLightConfig;
