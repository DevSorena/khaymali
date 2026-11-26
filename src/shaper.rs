//! Smart statistical traffic shaper for TLS 1.3 / HTTP/2 camouflage.
//!
//! Eliminates telltale fixed-size Noise/control packet lengths (such as small handshakes,
//! SOCKS5 requests, or keepalives) by aligning small records to realistic HTTP/2 TLS record
//! size buckets while keeping bulk transfer overhead negligible (<0.3%).

use crate::util::rand_range;

/// Realistic TLS 1.3 / HTTP/2 application_data record length buckets (bytes).
const H2_BUCKETS: [usize; 7] = [64, 128, 256, 512, 1024, 1400, 4096];

pub struct TrafficShaper {
    pad_max: usize,
    record_seq: u64,
}

impl TrafficShaper {
    pub fn new(pad_max: usize) -> Self {
        Self {
            pad_max,
            record_seq: 0,
        }
    }

    /// Compute padding length for a payload of `payload_len` bytes, strictly bounded by
    /// `self.pad_max` and `max_extra_allowed`.
    ///
    /// - On the first 4 records (handshake/initial HTTP/2 SETTINGS+HEADERS phase): aligns to the
    ///   nearest HTTP/2 bucket within `pad_max`, plus small jitter so identical Noise messages
    ///   never produce identical ciphertext record lengths.
    /// - On small interactive packets (`<= 1400` bytes): shapes toward realistic bucket sizes.
    /// - On bulk packets (`> 4096` bytes): applies tiny randomized jitter (`0..=min(pad_max, 32)`)
    ///   to preserve throughput while masking exact chunk boundaries.
    pub fn next_padding(&mut self, payload_len: usize, max_extra_allowed: usize) -> usize {
        self.record_seq = self.record_seq.saturating_add(1);
        let limit = self.pad_max.min(max_extra_allowed);
        if limit == 0 {
            return 0;
        }

        // Bulk transfer fast-path: tiny jitter only to preserve high throughput
        if payload_len > 4096 {
            return rand_range(0, limit.min(32));
        }

        // Initial flight (first 4 records): strong bucket shaping + jitter
        if self.record_seq <= 4 {
            if let Some(&bucket) = H2_BUCKETS.iter().find(|&&b| b >= payload_len) {
                let to_bucket = bucket.saturating_sub(payload_len);
                if to_bucket <= limit {
                    let jitter = rand_range(0, (limit - to_bucket).min(24));
                    return (to_bucket + jitter).min(limit);
                }
            }
            return rand_range(limit / 3, limit);
        }

        // Interactive / medium packets: align to bucket if within pad_max, else smooth random pad
        if let Some(&bucket) = H2_BUCKETS.iter().find(|&&b| b >= payload_len) {
            let to_bucket = bucket.saturating_sub(payload_len);
            if to_bucket <= limit {
                let jitter = rand_range(0, (limit - to_bucket).min(16));
                return (to_bucket + jitter).min(limit);
            }
        }
        rand_range(0, limit)
    }

    /// Suggest an optional split size for the very first record if a large burst arrives
    /// immediately after TLS handshake (mimics HTTP/2 SETTINGS + HEADERS split).
    pub fn first_flight_split(&self, available: usize) -> usize {
        if self.record_seq == 0 && available > 512 && self.pad_max > 0 {
            rand_range(180, 380).min(available)
        } else {
            available
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shaper_respects_bounds_and_keeps_bulk_overhead_low() {
        let mut s = TrafficShaper::new(128);
        for _ in 0..20 {
            let p = s.next_padding(96, 128);
            assert!(p <= 128);
        }
        for _ in 0..20 {
            let p = s.next_padding(14000, 128);
            assert!(p <= 32, "bulk padding must stay <= 32 bytes, got {p}");
        }
        let mut zero = TrafficShaper::new(0);
        assert_eq!(zero.next_padding(100, 100), 0);
    }

    #[test]
    fn shaper_splits_large_first_flight_burst() {
        let s = TrafficShaper::new(48);
        let first = s.first_flight_split(4096);
        assert!((180..=380).contains(&first));
    }
}
