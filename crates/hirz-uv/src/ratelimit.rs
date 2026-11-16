//! At most N approval prompts per RP id in any 60 second window. State is in memory only:
//! it limits prompt spam from a page or a local client within one running process, and
//! resets when the process restarts.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub const WINDOW: Duration = Duration::from_secs(60);
const MAX_TRACKED_RPS: usize = 1024;

#[derive(Debug, Default)]
pub struct RateLimiter {
    seen: HashMap<String, VecDeque<Instant>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Refused attempts are not recorded.
    pub fn allow(&mut self, rp_id: &str, now: Instant, per_minute: u32) -> bool {
        let limit = usize::try_from(per_minute).unwrap_or(usize::MAX);
        let key = rp_id.to_ascii_lowercase();
        if !self.seen.contains_key(&key) && self.seen.len() >= MAX_TRACKED_RPS {
            self.prune(now);
            if self.seen.len() >= MAX_TRACKED_RPS {
                return false;
            }
        }
        let times = self.seen.entry(key).or_default();
        while times.front().is_some_and(|t| expired(*t, now)) {
            times.pop_front();
        }
        if times.len() >= limit {
            return false;
        }
        times.push_back(now);
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
            assert!(r.allow(&format!("site{i}.example"), t0, 5));
        }
        assert!(!r.allow("new.example", t0, 5));
        assert!(r.allow("site1.example", t0, 5));
        assert!(r.allow("new.example", t0 + WINDOW, 5));
        assert_eq!(r.seen.len(), 1);
    }
}
