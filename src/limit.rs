//! The limits that keep any one client, address or allocation to its share, and the token
//! buckets that enforce the rates among them.

use std::hash::{BuildHasher, Hash, RandomState};
use std::time::{Duration, Instant};

/// How much outpost takes on. The defaults are sized for a few hundred games at a time on one
/// small VPS; tests make them smaller.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Rooms open at once; one more gets 503 from `POST /rooms`.
    pub rooms: usize,
    /// How fast rooms may be opened; faster gets 429. A new room comes with a full
    /// `room_bandwidth`, so this is what keeps that limit from being had again at will.
    pub rooms_opened: Rate,
    /// How long a room's credentials work. Its allocations end with it.
    pub room_lifetime: Duration,
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
    /// A TCP connection that has not allocated this long after opening is closed. That bounds how
    /// long one connection without credentials holds a place, though a client that reconnects
    /// can keep taking places again.
    pub tcp_setup: Duration,
    /// Answers sent over UDP to one IP address. Its source can be forged, so this is what keeps
    /// outpost from being used to flood someone else with answers.
    pub udp_answers: Rate,
    /// How many buckets those answers are counted in (`HashedBuckets`). Addresses that share
    /// one by chance share its rate, so it is far larger than the addresses expected at once.
    pub udp_answer_buckets: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            rooms: 10_000,
            rooms_opened: Rate {
                per_second: 1.0,
                burst: 60.0,
            },
            room_lifetime: Duration::from_secs(12 * 60 * 60),
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
            udp_answer_buckets: 65_536,
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
}

/// A fixed table of buckets, each key drawing on the one a keyed hash of it picks. A key never
/// gets more than one bucket's rate however many keys there are, and the table cannot be
/// filled up. Keys that land in the same bucket share it; the hash's key is random, so nobody
/// can choose keys that do.
pub struct HashedBuckets {
    rate: Rate,
    hasher: RandomState,
    buckets: Vec<Bucket>,
}

impl HashedBuckets {
    pub fn new(rate: Rate, size: usize, now: Instant) -> Self {
        HashedBuckets {
            rate,
            hasher: RandomState::new(),
            buckets: vec![Bucket::full(rate, now); size.max(1)],
        }
    }

    /// Whether `key` may have one more.
    pub fn allow(&mut self, key: impl Hash, now: Instant) -> bool {
        let index = self.hasher.hash_one(key) as usize % self.buckets.len();
        self.buckets[index].take(1.0, self.rate, now)
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
    fn a_key_gets_no_more_than_one_bucket_however_many_keys_there_are() {
        let start = Instant::now();
        let mut buckets = HashedBuckets::new(RATE, 65_536, start);
        for _ in 0..20 {
            assert!(buckets.allow("victim", start));
        }
        assert!(!buckets.allow("victim", start));
        assert!(
            buckets.allow("victim", at(start, 100)),
            "refilled at its rate"
        );

        // Many other keys neither raise its allowance nor, with room in the table, use it up.
        for key in 0..10_000 {
            buckets.allow(key, start);
        }
        assert!(!buckets.allow("victim", at(start, 100)));
        let mut fresh = HashedBuckets::new(RATE, 65_536, start);
        for key in 0..10_000 {
            fresh.allow(key, start);
        }
        assert!(fresh.allow("newcomer", start));
    }

    #[test]
    fn keys_in_the_same_bucket_share_it() {
        let start = Instant::now();
        let mut one = HashedBuckets::new(RATE, 1, start);
        for key in 0..20 {
            assert!(one.allow(key, start));
        }
        assert!(!one.allow("anyone", start));
    }
}
