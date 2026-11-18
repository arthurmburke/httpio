//! Indexed min-heap: one deadline per connection, without stale entries.
//! Updating or cancelling a timer is O(log n); an idle poll checks only the root.
//!
//! A connection is named by its slot in the engine's connection table, a
//! small dense integer, so finding its heap entry is an array read.

use crate::core::time::Instant;

/// `positions` entry of a key with no timer.
const UNSET: u32 = u32::MAX;

#[derive(Default)]
pub struct Timers {
    heap: Vec<(Instant, u32)>,
    /// Where each key's entry is in `heap`, indexed by key.
    positions: Vec<u32>,
}

impl Timers {
    fn position(&self, key: u32) -> Option<usize> {
        match self.positions.get(key as usize) {
            Some(&index) if index != UNSET => Some(index as usize),
            _ => None,
        }
    }

    pub fn set(&mut self, key: u32, deadline: Option<Instant>) {
        let Some(deadline) = deadline else {
            self.remove(key);
            return;
        };
        if let Some(index) = self.position(key) {
            if self.heap[index].0 == deadline {
                return;
            }
            self.heap[index].0 = deadline;
            self.repair(index);
        } else {
            if self.positions.len() <= key as usize {
                self.positions.resize(key as usize + 1, UNSET);
            }
            let index = self.heap.len();
            self.heap.push((deadline, key));
            self.positions[key as usize] = index as u32;
            self.up(index);
        }
    }

    pub fn remove(&mut self, key: u32) {
        let Some(index) = self.position(key) else {
            return;
        };
        self.positions[key as usize] = UNSET;
        self.heap.swap_remove(index);
        if index < self.heap.len() {
            self.positions[self.heap[index].1 as usize] = index as u32;
            self.repair(index);
        }
    }

    pub fn pop_due(&mut self, now: Instant) -> Option<u32> {
        let &(deadline, key) = self.heap.first()?;
        if deadline > now {
            return None;
        }
        self.remove(key);
        Some(key)
    }

    fn swap(&mut self, a: usize, b: usize) {
        self.heap.swap(a, b);
        self.positions[self.heap[a].1 as usize] = a as u32;
        self.positions[self.heap[b].1 as usize] = b as u32;
    }

    fn repair(&mut self, index: usize) {
        if index > 0 && self.heap[index].0 < self.heap[(index - 1) / 2].0 {
            self.up(index);
        } else {
            self.down(index);
        }
    }

    fn up(&mut self, mut index: usize) {
        while index > 0 {
            let parent = (index - 1) / 2;
            if self.heap[parent].0 <= self.heap[index].0 {
                break;
            }
            self.swap(parent, index);
            index = parent;
        }
    }

    fn down(&mut self, mut index: usize) {
        loop {
            let left = index * 2 + 1;
            if left >= self.heap.len() {
                break;
            }
            let right = left + 1;
            let child = if right < self.heap.len() && self.heap[right].0 < self.heap[left].0 {
                right
            } else {
                left
            };
            if self.heap[index].0 <= self.heap[child].0 {
                break;
            }
            self.swap(index, child);
            index = child;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::time::Duration;

    #[test]
    fn reschedule_cancel_and_reuse_keep_one_entry_per_connection() {
        let now = Instant::now();
        let mut timers = Timers::default();
        for i in 0..300 {
            timers.set(i, Some(now + Duration::from_secs(300 - u64::from(i))));
        }
        for i in 0..1000 {
            timers.set(0, Some(now + Duration::from_secs(i)));
        }
        assert_eq!(timers.heap.len(), 300);
        timers.set(1, Some(now));
        assert_eq!(timers.pop_due(now), Some(1));
        timers.remove(299);
        assert_eq!(timers.pop_due(now + Duration::from_secs(1)), None);
        timers.set(299, Some(now));
        assert_eq!(timers.pop_due(now), Some(299));
        let mut previous = now;
        while let Some(&(deadline, next)) = timers.heap.first() {
            assert!(deadline >= previous);
            previous = deadline;
            assert_eq!(timers.pop_due(deadline), Some(next));
            for (index, &(_, key)) in timers.heap.iter().enumerate() {
                assert_eq!(timers.positions[key as usize], index as u32);
            }
        }
        assert!(timers.positions.iter().all(|&p| p == UNSET));
    }
}
