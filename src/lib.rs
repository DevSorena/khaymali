//! Khaymali Tunnel v0.22.7 — library root.
//!
//! High-performance pure-Rust censorship-circumvention tunnel.
//! Architecture: Entry ↔ Bridge ↔ Exit with Noise_IK end-to-end encryption.
//! Includes hardened session resume, adaptive FEC, cluster mesh and harsh-network intelligence.
//!
//! This crate exposes all core modules used by the `khaymali` binary
//! and by integration / negative-security tests.

pub mod adapt;
pub mod alerts;
pub mod autopilot;
pub mod backup;
pub mod bridge;
pub mod camo;
pub mod cli;
pub mod carrier_swap;
pub mod cluster_lb;
pub mod cluster_mesh;
pub mod control;
pub mod dial_route;
pub mod engines;
pub mod entry;
pub mod exit;
pub mod fallback;
pub mod fleet;
pub mod forward;
pub mod harsh_nlp;
pub mod health;
pub mod hjson;
pub mod intelligence;
pub mod kani_nlp;
pub mod ktunnel;
pub mod l3;
pub mod ltm;
pub mod l3_wraps;
pub mod link;
pub mod mux;
pub mod node_cluster;
pub mod ops_suite;
pub mod pathtest;
pub mod pool;
pub mod recovery;
pub mod rescue;
pub mod revpath;
pub mod session_resume;
pub mod setup_bundle;
pub mod shaper;
pub mod spoof_carrier;
pub mod ssh_carrier;
pub mod sshfwd;
pub mod stats;
pub mod tgbot;
pub mod sysrun;
pub mod transport;
pub mod transport_engine;
pub mod udp;
pub mod udp_transport;
pub mod util;
pub mod watchdog;
pub mod ws_transport;
pub mod xray_engine;
