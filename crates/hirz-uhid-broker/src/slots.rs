//! Admission control: a uid range, one device per uid, a cap on concurrent devices and a
//! per-uid creation budget, so no account can churn kernel HID devices.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Device creations a uid may make in a burst, and how fast the budget comes back.
const BURST: u32 = 6;
const REFILL_SECS: u64 = 10;
/// A uid cannot get a new device sooner than this after its last one was destroyed.
const MIN_GAP: Duration = Duration::from_millis(250);
const MAX_TRACKED: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    BelowMinUid,
    AboveMaxUid,
    UidBusy,
    Full,
    RateLimited,
    TooSoon,
}

impl Refusal {
    pub fn reason(self) -> &'static str {
        match self {
            Self::BelowMinUid => "uid below the minimum",
            Self::AboveMaxUid => "uid above the maximum",
            Self::UidBusy => "uid already has a device",
            Self::Full => "connection limit reached",
            Self::RateLimited => "too many devices created recently",
            Self::TooSoon => "previous device destroyed a moment ago",
        }
    }
}

#[derive(Debug)]
struct Budget {
    tokens: u32,
    refilled: Instant,
    released: Option<Instant>,
}

impl Budget {
    fn refill(&mut self, now: Instant) {
        let steps = now.saturating_duration_since(self.refilled).as_secs() / REFILL_SECS;
        if steps == 0 {
            return;
        }
        let gained = u32::try_from(steps).unwrap_or(u32::MAX);
        self.tokens = self.tokens.saturating_add(gained).min(BURST);
        self.refilled = if self.tokens >= BURST {
            now
        } else {
            self.refilled
                .checked_add(Duration::from_secs(steps.saturating_mul(REFILL_SECS)))
                .unwrap_or(now)
        };
    }
}

#[derive(Debug, Default)]
struct State {
    active: HashSet<u32>,
    budgets: HashMap<u32, Budget>,
}

#[derive(Debug)]
pub struct Slots {
    state: Mutex<State>,
    min_uid: u32,
    max_uid: u32,
    max: usize,
}

#[derive(Debug)]
pub struct SlotGuard {
    slots: Arc<Slots>,
    uid: u32,
}

impl Slots {
    pub fn new(min_uid: u32, max_uid: u32, max: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            min_uid,
            max_uid,
            max,
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A poisoned lock only means a relay thread died; the state stays consistent because
        // every mutation is a single insert, remove or field update.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn check_range(&self, uid: u32) -> Result<(), Refusal> {
        if uid < self.min_uid {
            return Err(Refusal::BelowMinUid);
        }
        if uid > self.max_uid {
            return Err(Refusal::AboveMaxUid);
        }
        Ok(())
    }

    pub fn try_acquire_at(self: &Arc<Self>, uid: u32, now: Instant) -> Result<SlotGuard, Refusal> {
        self.check_range(uid)?;
        let mut guard = self.lock();
        let State { active, budgets } = &mut *guard;
        if active.contains(&uid) {
            return Err(Refusal::UidBusy);
        }
        if active.len() >= self.max {
            return Err(Refusal::Full);
        }
        if budgets.len() >= MAX_TRACKED && !budgets.contains_key(&uid) {
            budgets.retain(|id, b| {
                b.refill(now);
                active.contains(id) || b.tokens < BURST
            });
            if budgets.len() >= MAX_TRACKED {
                return Err(Refusal::Full);
            }
        }
        let budget = budgets.entry(uid).or_insert(Budget {
            tokens: BURST,
            refilled: now,
            released: None,
        });
        budget.refill(now);
        if let Some(released) = budget.released
            && now.saturating_duration_since(released) < MIN_GAP
        {
            return Err(Refusal::TooSoon);
        }
        if budget.tokens == 0 {
            return Err(Refusal::RateLimited);
        }
        budget.tokens = budget.tokens.saturating_sub(1);
        active.insert(uid);
        Ok(SlotGuard {
            slots: Arc::clone(self),
            uid,
        })
    }

    #[cfg(test)]
    pub fn active(&self) -> usize {
        self.lock().active.len()
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let mut guard = self.slots.lock();
        guard.active.remove(&self.uid);
        if let Some(budget) = guard.budgets.get_mut(&self.uid) {
            budget.released = Some(Instant::now());
        }
    }
}

/// At most one log line per uid every 30 seconds, with the number of lines left out, so a
/// client that connects in a loop cannot flood the journal.
#[derive(Debug, Default)]
pub struct RefusalLog {
    seen: HashMap<u32, (Instant, u32)>,
}

const LOG_EVERY: Duration = Duration::from_secs(30);
const MAX_LOGGED_UIDS: usize = 256;

impl RefusalLog {
    /// `Some(n)`: write a line now; `n` earlier refusals of this uid were not logged.
    pub fn note(&mut self, uid: u32, now: Instant) -> Option<u32> {
        if let Some((last, skipped)) = self.seen.get_mut(&uid) {
            if now.saturating_duration_since(*last) < LOG_EVERY {
                *skipped = skipped.saturating_add(1);
                return None;
            }
            let n = *skipped;
            *last = now;
            *skipped = 0;
            return Some(n);
        }
        if self.seen.len() >= MAX_LOGGED_UIDS {
            self.seen
                .retain(|_, (last, _)| now.saturating_duration_since(*last) < LOG_EVERY);
            if self.seen.len() >= MAX_LOGGED_UIDS {
                return None;
            }
        }
        self.seen.insert(uid, (now, 0));
        Some(0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    const MAX_UID: u32 = 60_513;

    fn slots(max: usize) -> Arc<Slots> {
        Slots::new(1000, MAX_UID, max)
    }

    #[test]
    fn one_device_per_uid_and_global_cap() {
        let slots = slots(2);
        let t = Instant::now() + Duration::from_secs(60);
        assert_eq!(
            slots.try_acquire_at(0, t).unwrap_err(),
            Refusal::BelowMinUid
        );
        assert_eq!(
            slots.try_acquire_at(999, t).unwrap_err(),
            Refusal::BelowMinUid
        );
        let a = slots.try_acquire_at(1000, t).unwrap();
        assert_eq!(slots.try_acquire_at(1000, t).unwrap_err(), Refusal::UidBusy);
        let _b = slots.try_acquire_at(1001, t).unwrap();
        assert_eq!(slots.try_acquire_at(1002, t).unwrap_err(), Refusal::Full);
        drop(a);
        assert_eq!(slots.active(), 1);
        let _a = slots
            .try_acquire_at(1000, t + Duration::from_secs(1))
            .unwrap();
    }

    #[test]
    fn nobody_and_dynamic_user_ids_are_refused() {
        let slots = slots(8);
        let t = Instant::now();
        assert!(slots.try_acquire_at(MAX_UID, t).is_ok());
        for uid in [60_514, 61_184, 65_519, 65_534, 65_535, 4_294_967_294] {
            assert_eq!(
                slots.try_acquire_at(uid, t).unwrap_err(),
                Refusal::AboveMaxUid,
                "uid {uid}"
            );
        }
        assert_eq!(slots.check_range(1000), Ok(()));
        assert_eq!(slots.check_range(999), Err(Refusal::BelowMinUid));
    }

    #[test]
    fn creations_are_rate_limited_per_uid() {
        let slots = slots(8);
        let base = Instant::now();
        for i in 1..=BURST {
            let g = slots
                .try_acquire_at(1000, base + Duration::from_secs(u64::from(i)))
                .unwrap();
            drop(g);
        }
        assert_eq!(
            slots
                .try_acquire_at(1000, base + Duration::from_secs(7))
                .unwrap_err(),
            Refusal::RateLimited
        );
        // Another uid has its own budget.
        assert!(slots.try_acquire_at(1001, base).is_ok());
        // One token comes back every ten seconds.
        let later = base + Duration::from_secs(11);
        let g = slots.try_acquire_at(1000, later).unwrap();
        drop(g);
        assert_eq!(
            slots
                .try_acquire_at(1000, later + Duration::from_secs(1))
                .unwrap_err(),
            Refusal::RateLimited
        );
        assert!(
            slots
                .try_acquire_at(1000, later + Duration::from_secs(12))
                .is_ok()
        );
    }

    #[test]
    fn a_destroyed_device_blocks_its_uid_for_a_moment() {
        let slots = slots(8);
        let t = Instant::now();
        drop(slots.try_acquire_at(1000, t).unwrap());
        let soon = Instant::now() + Duration::from_millis(10);
        assert_eq!(
            slots.try_acquire_at(1000, soon).unwrap_err(),
            Refusal::TooSoon
        );
        assert!(
            slots
                .try_acquire_at(1000, Instant::now() + Duration::from_secs(1))
                .is_ok()
        );
    }

    #[test]
    fn the_budget_table_stays_bounded() {
        let slots = Slots::new(1000, u32::MAX, 8);
        let t = Instant::now();
        let mut refused = 0;
        for uid in 1000..1000 + 3000 {
            match slots.try_acquire_at(uid, t) {
                Ok(g) => drop(g),
                Err(Refusal::Full) => refused += 1,
                Err(other) => panic!("{other:?}"),
            }
        }
        assert!(refused > 0);
        assert!(slots.lock().budgets.len() <= MAX_TRACKED);
    }

    #[test]
    fn refusal_log_limits_lines_per_uid() {
        let mut log = RefusalLog::default();
        let t = Instant::now();
        assert_eq!(log.note(1000, t), Some(0));
        for i in 1..=100 {
            assert_eq!(log.note(1000, t + Duration::from_millis(i)), None);
        }
        assert_eq!(log.note(1001, t), Some(0));
        assert_eq!(log.note(1000, t + Duration::from_secs(31)), Some(100));
        assert_eq!(log.note(1000, t + Duration::from_secs(32)), None);
    }

    #[test]
    fn refusal_log_table_stays_bounded() {
        let mut log = RefusalLog::default();
        let t = Instant::now();
        for uid in 0..1000 {
            let _ = log.note(uid, t);
        }
        assert!(log.seen.len() <= MAX_LOGGED_UIDS);
        assert_eq!(log.note(5000, t + Duration::from_secs(31)), Some(0));
    }
}
