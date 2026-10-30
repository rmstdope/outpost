//! The limits that keep any one client, address or allocation to its share, and the token
//! buckets that enforce the rates among them.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// How much outpost takes on. The defaults are sized for a few hundred games at a time on one
/// small VPS; tests make them smaller.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Allocations in all; one beyond gets 508 (Insufficient Capacity).
    pub allocations: usize,
    /// Allocations from one IP address; one beyond gets 486 (Allocation Quota Reached). Room for
    /// two players behind one home router, each on UDP and TCP and two network interfaces.
    pub allocations_per_address: usize,
    /// Bytes one room may relay, its players together, counting every message's own bytes as
    /// well as its data. Kept per room, so that allocating again does not refill it. A game
    /// sends a few kilobytes a second; the burst lets a ROM through in seconds. What does not
    /// fit is dropped, as if lost on the way.
    pub room_bandwidth: Rate,
    /// TCP connections in all, and from one IP address. One beyond is closed at once.
    pub tcp_connections: usize,
    pub tcp_connections_per_address: usize,
    /// A TCP connection that sends no whole message for this long is closed. A game in
    /// progress sends every few seconds.
    pub tcp_idle: Duration,
    /// A TCP connection that has not allocated this long after opening is closed, so that
    /// connections without credentials cannot hold the places.
    pub tcp_setup: Duration,
    /// Answers sent over UDP to one IP address. Its source can be forged, so this is what keeps
    /// outpost from being used to flood someone else with answers.
    pub udp_answers: Rate,
    /// IP addresses whose UDP answers are tracked at once. Beyond that, new addresses share
    /// `udp_answers_overflow` until the next sweep.
    pub udp_answer_addresses: usize,
    pub udp_answers_overflow: Rate,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            allocations: 1000,
            allocations_per_address: 16,
            room_bandwidth: Rate {
                per_second: 512.0 * 1024.0,
                burst: 2.0 * 1024.0 * 1024.0,
            },
            tcp_connections: 1000,
            tcp_connections_per_address: 16,
            tcp_idle: Duration::from_secs(120),
            tcp_setup: Duration::from_secs(30),
            udp_answers: Rate {
                per_second: 20.0,
                burst: 40.0,
            },
            udp_answer_addresses: 100_000,
            udp_answers_overflow: Rate {
                per_second: 1000.0,
                burst: 2000.0,
            },
        }
    }
}

/// A steady rate with room for bursts, in whatever unit is being counted.
#[derive(Clone, Copy, Debug)]
pub struct Rate {
    pub per_second: f64,
    pub burst: f64,
}

#[derive(Clone, Copy, Debug)]
pub struct Bucket {
    tokens: f64,
    updated: Instant,
}

impl Bucket {
    pub fn full(rate: Rate, now: Instant) -> Self {
        Bucket {
            tokens: rate.burst,
            updated: now,
        }
    }

    fn refill(&mut self, rate: Rate, now: Instant) {
        let elapsed = now.saturating_duration_since(self.updated).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate.per_second).min(rate.burst);
        self.updated = self.updated.max(now);
    }

    /// Takes `amount` if the bucket holds that much, and answers whether it did.
    pub fn take(&mut self, amount: f64, rate: Rate, now: Instant) -> bool {
        self.refill(rate, now);
        let enough = self.tokens >= amount;
        if enough {
            self.tokens -= amount;
        }
        enough
    }

    fn is_full(mut self, rate: Rate, now: Instant) -> bool {
        self.refill(rate, now);
        self.tokens >= rate.burst
    }
}

/// One bucket per key, for at most `capacity` keys at a time; keys beyond that share one
/// overflow bucket.
pub struct Limiter<K> {
    rate: Rate,
    capacity: usize,
    buckets: HashMap<K, Bucket>,
    overflow_rate: Rate,
    overflow: Bucket,
}

impl<K: Hash + Eq> Limiter<K> {
    pub fn new(rate: Rate, capacity: usize, overflow: Rate) -> Self {
        Limiter {
            rate,
            capacity,
            buckets: HashMap::new(),
            overflow_rate: overflow,
            overflow: Bucket::full(overflow, Instant::now()),
        }
    }

    /// Whether `key` may have one more. A key not seen before shares the overflow while
    /// `capacity` keys are tracked.
    pub fn allow(&mut self, key: K, now: Instant) -> bool {
        if let Some(bucket) = self.buckets.get_mut(&key) {
            return bucket.take(1.0, self.rate, now);
        }
        if self.buckets.len() >= self.capacity {
            return self.overflow.take(1.0, self.overflow_rate, now);
        }
        let mut bucket = Bucket::full(self.rate, now);
        let allowed = bucket.take(1.0, self.rate, now);
        self.buckets.insert(key, bucket);
        allowed
    }

    /// Forgets the keys whose buckets have filled up again: they are as good as unseen.
    pub fn sweep(&mut self, now: Instant) {
        let rate = self.rate;
        self.buckets.retain(|_, bucket| !bucket.is_full(rate, now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RATE: Rate = Rate {
        per_second: 10.0,
        burst: 20.0,
    };

    fn at(start: Instant, millis: u64) -> Instant {
        start + Duration::from_millis(millis)
    }

    #[test]
    fn a_bucket_gives_its_burst_at_once_and_then_its_rate() {
        let start = Instant::now();
        let mut bucket = Bucket::full(RATE, start);
        assert!(bucket.take(20.0, RATE, start));
        assert!(!bucket.take(1.0, RATE, start));
        assert!(
            !bucket.take(2.0, RATE, at(start, 100)),
            "one token after 100 ms"
        );
        assert!(bucket.take(1.0, RATE, at(start, 100)));
        assert!(bucket.take(10.0, RATE, at(start, 1100)));
        assert!(
            !bucket.take(25.0, RATE, at(start, 60_000)),
            "never more than the burst"
        );
        assert!(bucket.take(20.0, RATE, at(start, 60_000)));
    }

    #[test]
    fn a_bucket_ignores_time_going_backwards() {
        let start = Instant::now();
        let mut bucket = Bucket::full(RATE, at(start, 1000));
        assert!(bucket.take(20.0, RATE, at(start, 1000)));
        assert!(!bucket.take(1.0, RATE, start));
        assert!(
            !bucket.take(1.0, RATE, at(start, 1000)),
            "no refill from the detour"
        );
    }

    #[test]
    fn a_limiter_keeps_one_bucket_per_key() {
        let start = Instant::now();
        let mut limiter = Limiter::new(RATE, 10, RATE);
        for _ in 0..20 {
            assert!(limiter.allow("a", start));
        }
        assert!(!limiter.allow("a", start));
        assert!(limiter.allow("b", start));
        assert!(limiter.allow("a", at(start, 100)));
    }

    #[test]
    fn a_full_limiter_lets_new_keys_share_its_overflow_until_swept() {
        let start = Instant::now();
        let overflow = Rate {
            per_second: 0.0,
            burst: 2.0,
        };
        let mut limiter = Limiter::new(RATE, 2, overflow);
        assert!(limiter.allow(1, start));
        assert!(limiter.allow(2, start));
        assert!(limiter.allow(3, start), "from the overflow");
        assert!(limiter.allow(4, start), "from the overflow");
        assert!(!limiter.allow(3, start), "the overflow is empty");
        assert!(limiter.allow(1, start), "known keys still have their own");

        limiter.sweep(at(start, 50));
        assert!(!limiter.allow(5, at(start, 50)), "nothing has refilled yet");
        limiter.sweep(at(start, 1000));
        assert!(limiter.allow(5, at(start, 1000)));
        assert!(
            limiter.allow(5, at(start, 1000)),
            "now with a bucket of its own"
        );
    }
}
