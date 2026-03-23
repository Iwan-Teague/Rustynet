#![forbid(unsafe_code)]

//! Rate limiting for relay sessions using token bucket algorithm.

use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct RateLimiter {
    pub max_pps: u64,
    pub max_bps: u64,
    pub max_sessions_per_node: usize,
    buckets: HashMap<String, TokenBucket>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            max_pps: 10_000,
            max_bps: 100_000_000, // 100 Mbps
            max_sessions_per_node: 8,
            buckets: HashMap::new(),
        }
    }
}

impl RateLimiter {
    pub fn check_packet(&mut self, node_id: &str, packet_size_bytes: usize) -> bool {
        let bucket = self
            .buckets
            .entry(node_id.to_string())
            .or_insert_with(|| TokenBucket::new(self.max_pps, self.max_bps));

        bucket.check_and_consume(1, packet_size_bytes * 8)
    }
}

#[derive(Debug, Clone)]
struct TokenBucket {
    max_pps: u64,
    max_bps: u64,
    packet_tokens: f64,
    bit_tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max_pps: u64, max_bps: u64) -> Self {
        Self {
            max_pps,
            max_bps,
            packet_tokens: max_pps as f64,
            bit_tokens: max_bps as f64,
            last_refill: Instant::now(),
        }
    }

    fn check_and_consume(&mut self, packets: u64, bits: usize) -> bool {
        self.refill();

        if self.packet_tokens >= packets as f64 && self.bit_tokens >= bits as f64 {
            self.packet_tokens -= packets as f64;
            self.bit_tokens -= bits as f64;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;

        self.packet_tokens =
            (self.packet_tokens + elapsed * self.max_pps as f64).min(self.max_pps as f64);

        self.bit_tokens =
            (self.bit_tokens + elapsed * self.max_bps as f64).min(self.max_bps as f64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_rate_limiter_accepts_within_limit() {
        let mut limiter = RateLimiter::default();

        // Should accept packets within rate limit
        for _ in 0..100 {
            assert!(limiter.check_packet("node-a", 1000));
        }
    }

    #[test]
    fn test_rate_limiter_drops_beyond_limit() {
        let mut limiter = RateLimiter {
            max_pps: 10,
            max_bps: 10_000,
            max_sessions_per_node: 8,
            buckets: HashMap::new(),
        };

        // Exhaust tokens
        for _ in 0..10 {
            assert!(limiter.check_packet("node-a", 100));
        }

        // Next packet should be dropped
        assert!(!limiter.check_packet("node-a", 100));
    }

    #[test]
    fn test_rate_limiter_refills_over_time() {
        let mut limiter = RateLimiter {
            max_pps: 10,
            max_bps: 10_000,
            max_sessions_per_node: 8,
            buckets: HashMap::new(),
        };

        // Exhaust tokens
        for _ in 0..10 {
            assert!(limiter.check_packet("node-a", 100));
        }

        // Should be rate limited
        assert!(!limiter.check_packet("node-a", 100));

        // Wait for refill
        thread::sleep(Duration::from_millis(150));

        // Should accept again
        assert!(limiter.check_packet("node-a", 100));
    }

    #[test]
    fn test_rate_limiter_per_node_isolation() {
        let mut limiter = RateLimiter {
            max_pps: 10,
            max_bps: 10_000,
            max_sessions_per_node: 8,
            buckets: HashMap::new(),
        };

        // Exhaust tokens for node-a
        for _ in 0..10 {
            assert!(limiter.check_packet("node-a", 100));
        }

        // node-a should be rate limited
        assert!(!limiter.check_packet("node-a", 100));

        // node-b should still have tokens
        assert!(limiter.check_packet("node-b", 100));
    }
}
