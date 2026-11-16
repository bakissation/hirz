//! Admission control: one device per uid and a cap on concurrent devices.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    BelowMinUid,
    UidBusy,
    Full,
}

impl Refusal {
    pub fn reason(self) -> &'static str {
        match self {
            Self::BelowMinUid => "uid below the minimum",
            Self::UidBusy => "uid already has a device",
            Self::Full => "connection limit reached",
        }
    }
}

#[derive(Debug)]
pub struct Slots {
    active: Mutex<HashSet<u32>>,
    min_uid: u32,
    max: usize,
}

#[derive(Debug)]
pub struct SlotGuard {
    slots: Arc<Slots>,
    uid: u32,
}

impl Slots {
    pub fn new(min_uid: u32, max: usize) -> Arc<Self> {
        Arc::new(Self {
            active: Mutex::new(HashSet::new()),
            min_uid,
            max,
        })
    }

    fn lock(&self) -> MutexGuard<'_, HashSet<u32>> {
        // A poisoned lock only means a relay thread died; the set itself stays consistent
        // because every mutation is a single insert or remove.
        self.active.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn try_acquire(self: &Arc<Self>, uid: u32) -> Result<SlotGuard, Refusal> {
        if uid < self.min_uid {
            return Err(Refusal::BelowMinUid);
        }
        let mut active = self.lock();
        if active.contains(&uid) {
            return Err(Refusal::UidBusy);
        }
        if active.len() >= self.max {
            return Err(Refusal::Full);
        }
        active.insert(uid);
        Ok(SlotGuard {
            slots: Arc::clone(self),
            uid,
        })
    }

    #[cfg(test)]
    pub fn active(&self) -> usize {
        self.lock().len()
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.slots.lock().remove(&self.uid);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn one_device_per_uid_and_global_cap() {
        let slots = Slots::new(1000, 2);
        assert_eq!(slots.try_acquire(0).unwrap_err(), Refusal::BelowMinUid);
        assert_eq!(slots.try_acquire(999).unwrap_err(), Refusal::BelowMinUid);
        let a = slots.try_acquire(1000).unwrap();
        assert_eq!(slots.try_acquire(1000).unwrap_err(), Refusal::UidBusy);
        let _b = slots.try_acquire(1001).unwrap();
        assert_eq!(slots.try_acquire(1002).unwrap_err(), Refusal::Full);
        drop(a);
        assert_eq!(slots.active(), 1);
        let _a = slots.try_acquire(1000).unwrap();
    }
}
