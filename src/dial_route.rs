//! Smart Dial Route State Machine (`auto | gre | public`, `src/dial_route.rs`).
//!
//! Ported from Khaymali's `dial.go` & `khaymali.sh dial`.

use anyhow::{bail, Result};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const GRE_RETURN_CONSECUTIVE_OK: u32 = 5;
pub const GRE_FAILBACK_LOCK: Duration = Duration::from_secs(30 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialMode {
    Auto,
    Gre,
    Public,
}

impl DialMode {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(DialMode::Auto),
            "gre" | "inner" => Ok(DialMode::Gre),
            "public" | "pub" => Ok(DialMode::Public),
            other => bail!("invalid dial route mode '{other}' (expected auto|gre|public)"),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            DialMode::Auto => "auto",
            DialMode::Gre => "gre",
            DialMode::Public => "public",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActiveRoute {
    Gre,
    Public,
}

impl ActiveRoute {
    pub fn as_str(self) -> &'static str {
        match self {
            ActiveRoute::Gre => "gre",
            ActiveRoute::Public => "public",
        }
    }
}

#[derive(Clone, Debug)]
pub struct DialRouteSnapshot {
    pub mode: DialMode,
    pub active: ActiveRoute,
    pub gre_addr: String,
    pub public_addr: String,
    pub gre_ok_streak: u32,
    pub lock_remaining_secs: u64,
    pub switches: u64,
}

struct Inner {
    mode: DialMode,
    active: ActiveRoute,
    gre_addr: String,
    public_addr: String,
    gre_ok_streak: u32,
    gre_locked_until: Option<Instant>,
    just_returned_to_gre: bool,
    switches: u64,
}

pub struct DialRouter {
    inner: Mutex<Inner>,
}

impl DialRouter {
    pub fn new(mode: DialMode, gre_addr: String, public_addr: String) -> Self {
        let active = match mode {
            DialMode::Public => ActiveRoute::Public,
            DialMode::Gre | DialMode::Auto => ActiveRoute::Gre,
        };
        Self {
            inner: Mutex::new(Inner {
                mode,
                active,
                gre_addr,
                public_addr,
                gre_ok_streak: 0,
                gre_locked_until: None,
                just_returned_to_gre: false,
                switches: 0,
            }),
        }
    }

    pub fn set_mode(&self, mode: DialMode) {
        let mut g = self.inner.lock().unwrap();
        g.mode = mode;
        match mode {
            DialMode::Gre => {
                g.active = ActiveRoute::Gre;
                g.gre_locked_until = None;
            }
            DialMode::Public => {
                g.active = ActiveRoute::Public;
            }
            DialMode::Auto => {}
        }
    }

    pub fn current_addr(&self) -> String {
        let g = self.inner.lock().unwrap();
        match g.active {
            ActiveRoute::Gre => g.gre_addr.clone(),
            ActiveRoute::Public => g.public_addr.clone(),
        }
    }

    pub fn tick_at(
        &self,
        now: Instant,
        gre_probe_ok: bool,
        session_connected: bool,
    ) -> Option<ActiveRoute> {
        let mut g = self.inner.lock().unwrap();
        if g.mode != DialMode::Auto {
            return None;
        }
        match g.active {
            ActiveRoute::Gre => {
                if !gre_probe_ok && !session_connected {
                    g.active = ActiveRoute::Public;
                    g.gre_ok_streak = 0;
                    g.switches += 1;
                    if g.just_returned_to_gre {
                        g.gre_locked_until = Some(now + GRE_FAILBACK_LOCK);
                        g.just_returned_to_gre = false;
                    }
                    return Some(ActiveRoute::Public);
                }
                if session_connected {
                    g.just_returned_to_gre = false;
                }
            }
            ActiveRoute::Public => {
                if let Some(until) = g.gre_locked_until {
                    if now < until {
                        return None;
                    }
                    g.gre_locked_until = None;
                }
                if gre_probe_ok {
                    g.gre_ok_streak = g.gre_ok_streak.saturating_add(1);
                    if g.gre_ok_streak >= GRE_RETURN_CONSECUTIVE_OK {
                        g.active = ActiveRoute::Gre;
                        g.gre_ok_streak = 0;
                        g.just_returned_to_gre = true;
                        g.switches += 1;
                        return Some(ActiveRoute::Gre);
                    }
                } else {
                    g.gre_ok_streak = 0;
                }
            }
        }
        None
    }

    pub fn note_gre_connect_failed(&self, now: Instant) -> bool {
        let mut g = self.inner.lock().unwrap();
        if g.mode == DialMode::Auto && g.active == ActiveRoute::Gre {
            g.active = ActiveRoute::Public;
            g.gre_ok_streak = 0;
            g.switches += 1;
            if g.just_returned_to_gre {
                g.gre_locked_until = Some(now + GRE_FAILBACK_LOCK);
                g.just_returned_to_gre = false;
            }
            return true;
        }
        false
    }

    pub fn snapshot(&self, now: Instant) -> DialRouteSnapshot {
        let g = self.inner.lock().unwrap();
        let lock_remaining_secs = g
            .gre_locked_until
            .and_then(|u| u.checked_duration_since(now))
            .map(|d| d.as_secs())
            .unwrap_or(0);
        DialRouteSnapshot {
            mode: g.mode,
            active: g.active,
            gre_addr: g.gre_addr.clone(),
            public_addr: g.public_addr.clone(),
            gre_ok_streak: g.gre_ok_streak,
            lock_remaining_secs,
            switches: g.switches,
        }
    }

    pub fn status_json(&self) -> String {
        let s = self.snapshot(Instant::now());
        format!(
            "{{\"ok\":true,\"mode\":\"{}\",\"active\":\"{}\",\"gre_addr\":\"{}\",\"public_addr\":\"{}\",\"gre_ok_streak\":{},\"lock_remaining_secs\":{},\"switches\":{}}}\n",
            s.mode.as_str(),
            s.active.as_str(),
            s.gre_addr,
            s.public_addr,
            s.gre_ok_streak,
            s.lock_remaining_secs,
            s.switches,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_switches_to_public_returns_after_5_and_locks_30m_on_bounce() {
        let t0 = Instant::now();
        let r = DialRouter::new(DialMode::Auto, "10.10.10.1:443".into(), "203.0.113.5:443".into());
        assert_eq!(r.tick_at(t0, false, false), Some(ActiveRoute::Public));
        assert_eq!(r.current_addr(), "203.0.113.5:443");
        for i in 1..=4 {
            assert_eq!(r.tick_at(t0 + Duration::from_secs(60 * i), true, true), None);
        }
        assert_eq!(r.tick_at(t0 + Duration::from_secs(300), true, true), Some(ActiveRoute::Gre));
        let t_fail = t0 + Duration::from_secs(305);
        assert!(r.note_gre_connect_failed(t_fail));
        assert_eq!(r.current_addr(), "203.0.113.5:443");
        for i in 1..=10 {
            assert_eq!(r.tick_at(t_fail + Duration::from_secs(60 * i), true, true), None);
        }
        let t_unlock = t_fail + GRE_FAILBACK_LOCK + Duration::from_secs(1);
        for i in 0..4 {
            assert_eq!(r.tick_at(t_unlock + Duration::from_secs(60 * i), true, true), None);
        }
        assert_eq!(r.tick_at(t_unlock + Duration::from_secs(240), true, true), Some(ActiveRoute::Gre));
    }
}
