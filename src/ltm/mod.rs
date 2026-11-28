//! Linux Tunnel Manager — classic kernel tunnels + Khaymali Light.
//!
//! Integrated into the main Khaymali binary:
//!   khaymali tunnels              interactive menu
//!   khaymali tunnels-restore      boot-time restore
//!   khaymali tunnels-clean        remove temporary interfaces
//!   khaymali tunnels-bench        auto benchmark (iperf3 / TCP fallback)
//!   khaymali light                run Khaymali Light data plane
//!
//! Uses [`crate::sysrun`] for all kernel commands so dry-run / --plan works.

pub mod config;
pub mod registry;
pub mod drivers;
pub mod cleanup;
pub mod persistence;
pub mod menu;
pub mod kmlight;
pub mod benchmark;
pub mod qos;

pub use menu::run_menu;
pub use persistence::restore_all;
pub use cleanup::auto_cleanup;
