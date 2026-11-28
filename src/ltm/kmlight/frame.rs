//! DNS-shaped recognition header (parity with original design).

use std::sync::atomic::{AtomicU32, Ordering};

pub const HEADER_LEN: usize = 37;
const TOKEN_LEN: usize = 6;
const TOKEN_OFF: usize = 13;

pub struct Framer {
    template: [u8; HEADER_LEN],
    token: [u8; TOKEN_LEN],
    tag: AtomicU32,
}

fn simple_hash(s: &str) -> [u8; 32] {
    // FNV-1a 64 expanded into 32 bytes (good enough as recognition tag)
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        let v = h.wrapping_add(i * 0x9e3779b97f4a7c15);
        out[(i * 8) as usize..((i + 1) * 8) as usize].copy_from_slice(&v.to_le_bytes());
    }
    out
}

impl Framer {
    pub fn new(secret: &str) -> Self {
        let sum = simple_hash(&format!("khaymali-light-tag:{secret}"));
        let mut token = [0u8; TOKEN_LEN];
        token.copy_from_slice(&sum[..TOKEN_LEN]);
        let mut f = Framer {
            template: [0u8; HEADER_LEN],
            token,
            tag: AtomicU32::new(0xA5A5_1234),
        };
        f.build_template();
        f
    }

    fn label_bytes(dst: &mut [u8], seed: u64) {
        const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let mut x = seed;
        for b in dst.iter_mut() {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = ALPHA[(x >> 33) as usize % ALPHA.len()];
        }
    }

    fn build_template(&mut self) {
        let d = &mut self.template;
        d[2] = 0x01;
        d[3] = 0x00;
        d[4] = 0x00;
        d[5] = 0x01;
        d[12] = 0x0f;
        Self::label_bytes(&mut d[13..28], 1);
        d[TOKEN_OFF..TOKEN_OFF + TOKEN_LEN].copy_from_slice(&self.token);
        d[28] = 0x03;
        Self::label_bytes(&mut d[29..32], 2);
        d[32] = 0x00;
        d[33] = 0x00;
        d[34] = 0x01;
        d[35] = 0x00;
        d[36] = 0x01;
    }

    pub fn stamp(&self, dst: &mut [u8]) {
        dst[..HEADER_LEN].copy_from_slice(&self.template);
        let t = self.tag.fetch_add(1, Ordering::Relaxed);
        dst[0] = t as u8;
        dst[1] = (t >> 8) as u8;
    }

    pub fn valid(&self, pkt: &[u8]) -> bool {
        pkt.len() >= HEADER_LEN && pkt[TOKEN_OFF..TOKEN_OFF + TOKEN_LEN] == self.token
    }
}
