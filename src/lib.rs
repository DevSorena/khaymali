//! Khaymali Tunnel v0.15.1 library root.
//!
//! Exposes core modules for both the `khaymali` binary and real integration/negative security
//! tests in `tests/neg_security.rs`.

pub mod adapt;
pub mod bridge;
pub mod camo;
pub mod control;
pub mod entry;
pub mod exit;
pub mod fallback;
pub mod fleet;
pub mod forward;
pub mod health;
pub mod intelligence;
pub mod kani_nlp;
pub mod ktunnel;
pub mod l3;
pub mod link;
pub mod mux;
pub mod recovery;
pub mod session_resume;
pub mod shaper;
pub mod stats;
pub mod transport;
pub mod transport_engine;
pub mod udp;
pub mod udp_transport;
pub mod util;
pub mod watchdog;
