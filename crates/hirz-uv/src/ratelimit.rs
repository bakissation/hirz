//! At most N approval prompts per key (an RP id, or a fixed key for pairing, removal and
//! selection prompts) in any 60 second window, and at most [`GLOBAL_FACTOR`] times N across all
//! keys, so a page that moves between host names gains no new budget without bound. State is in
//! memory only: it limits prompt spam from a page or a local client within one running process,
//! and resets when the process restarts.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub const WINDOW: Duration = Duration::from_secs(60);
pub const GLOBAL_FACTOR: u32 = 3;
const MAX_TRACKED_RPS: usize = 1024;

#[derive(Debug, Default)]
pub struct RateLimiter {
    seen: HashMap<String, VecDeque<Instant>>,
    all: VecDeque<Instant>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether [`RateLimiter::allow`] would admit the attempt, without recording it.
    pub fn check(&mut self, key: &str, now: Instant, per_minute: u32) -> bool {
        let limit = usize::try_from(per_minute).unwrap_or(usize::MAX);
        let global_limit = limit.saturating_mul(usize::try_from(GLOBAL_FACTOR).unwrap_or(1));
        let key = key.to_ascii_lowercase();
        while self.all.front().is_some_and(|t| expired(*t, now)) {
            self.all.pop_front();
        }
        if self.all.len() >= global_limit {
            return false;
        }
        if !self.seen.contains_key(&key) && self.seen.len() >= MAX_TRACKED_RPS {
            self.prune(now);
            if self.seen.len() >= MAX_TRACKED_RPS {
                return false;
            }
        }
        match self.seen.get_mut(&key) {
            Some(times) => {
                while times.front().is_some_and(|t| expired(*t, now)) {
                    times.pop_front();
                }
                times.len() < limit
            }
            None => true,
        }
    }

    /// Refused attempts are not recorded.
    pub fn allow(&mut self, key: &str, now: Instant, per_minute: u32) -> bool {
        if !self.check(key, now, per_minute) {
            return false;
        }
        self.seen
            .entry(key.to_ascii_lowercase())
            .or_default()
            .push_back(now);
        self.all.push_back(now);
        true
    }

    fn prune(&mut self, now: Instant) {
        self.seen.retain(|_, times| {
            times.retain(|t| !expired(*t, now));
            !times.is_empty()
        });
    }
}

fn expired(t: Instant, now: Instant) -> bool {
    now.checked_duration_since(t).is_some_and(|d| d >= WINDOW)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn per_rp_window() {
        let mut r = RateLimiter::new();
        let t0 = Instant::now();
        for i in 0..3 {
            assert!(r.allow("example.com", t0 + Duration::from_secs(i), 3));
        }
        assert!(!r.allow("example.com", t0 + Duration::from_secs(10), 3));
        assert!(!r.allow("EXAMPLE.com", t0 + Duration::from_secs(10), 3));
        assert!(r.allow("other.example", t0 + Duration::from_secs(10), 3));
        assert!(r.allow("example.com", t0 + Duration::from_secs(60), 3));
        assert!(!r.allow("example.com", t0 + Duration::from_secs(60), 3));
        assert!(r.allow("example.com", t0 + Duration::from_secs(62), 3));
    }

    #[test]
    fn bounded_memory() {
        let mut r = RateLimiter::new();
        let t0 = Instant::now();
        for i in 0..MAX_TRACKED_RPS {
            r.seen
                .insert(format!("site{i}.example"), VecDeque::from([t0]));
        }
        assert!(!r.allow("new.example", t0, 5));
        assert!(r.allow("site1.example", t0, 5));
        assert!(r.allow("new.example", t0 + WINDOW, 5));
        assert_eq!(r.seen.len(), 1);
    }

    #[test]
    fn check_does_not_record() {
        let mut r = RateLimiter::new();
        let t0 = Instant::now();
        for _ in 0..50 {
            assert!(r.check("a.example", t0, 2));
        }
        assert!(r.allow("a.example", t0, 2));
        assert!(r.allow("a.example", t0, 2));
        assert!(!r.check("a.example", t0, 2));
        assert!(!r.allow("a.example", t0, 2));
        assert!(r.check("b.example", t0, 2));
    }

    #[test]
    fn global_window_caps_many_keys() {
        let mut r = RateLimiter::new();
        let t0 = Instant::now();
        for i in 0..15 {
            assert!(r.allow(&format!("sub{i}.example.com"), t0, 5), "{i}");
        }
        assert!(!r.allow("another.example.com", t0, 5));
        assert!(!r.allow("sub0.example.com", t0, 5));
        assert!(r.allow("another.example.com", t0 + WINDOW, 5));
    }

    #[test]
    fn a_refusal_by_key_does_not_use_the_global_budget() {
        let mut r = RateLimiter::new();
        let t0 = Instant::now();
        for _ in 0..5 {
            assert!(r.allow("a.example", t0, 5));
        }
        for _ in 0..20 {
            assert!(!r.allow("a.example", t0, 5));
        }
        assert!(r.allow("b.example", t0, 5));
        assert_eq!(r.all.len(), 6);
    }
}
