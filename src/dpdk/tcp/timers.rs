//! Indexed min-heap: one deadline per connection, without stale entries.
//! Updating or cancelling a timer is O(log n); an idle poll checks only the root.

use super::tcb::FourTuple;
use crate::core::hashmap::HashMap;
use std::time::Instant;

#[derive(Default)]
pub(super) struct Timers {
    heap: Vec<(Instant, FourTuple)>,
    positions: HashMap<FourTuple, usize>,
}

impl Timers {
    pub fn set(&mut self, tuple: FourTuple, deadline: Option<Instant>) {
        let Some(deadline) = deadline else {
            self.remove(tuple);
            return;
        };
        if let Some(&index) = self.positions.get(&tuple) {
            self.heap[index].0 = deadline;
            self.repair(index);
        } else {
            let index = self.heap.len();
            self.heap.push((deadline, tuple));
            self.positions.insert(tuple, index);
            self.up(index);
        }
    }

    pub fn remove(&mut self, tuple: FourTuple) {
        let Some(index) = self.positions.remove(&tuple) else {
            return;
        };
        self.heap.swap_remove(index);
        if index < self.heap.len() {
            *self.positions.get_mut(&self.heap[index].1).unwrap() = index;
            self.repair(index);
        }
    }

    pub fn pop_due(&mut self, now: Instant) -> Option<FourTuple> {
        let &(deadline, tuple) = self.heap.first()?;
        if deadline > now {
            return None;
        }
        self.remove(tuple);
        Some(tuple)
    }

    fn swap(&mut self, a: usize, b: usize) {
        self.heap.swap(a, b);
        *self.positions.get_mut(&self.heap[a].1).unwrap() = a;
        *self.positions.get_mut(&self.heap[b].1).unwrap() = b;
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
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn tuple(port: u16) -> FourTuple {
        FourTuple {
            local_ip: Ipv4Addr::LOCALHOST,
            local_port: port,
            remote_ip: Ipv4Addr::LOCALHOST,
            remote_port: 80,
        }
    }

    #[test]
    fn reschedule_cancel_and_reuse_keep_one_entry_per_connection() {
        let now = Instant::now();
        let mut timers = Timers::default();
        for i in 0..300 {
            timers.set(
                tuple(i),
                Some(now + Duration::from_secs(300 - u64::from(i))),
            );
        }
        for i in 0..1000 {
            timers.set(tuple(0), Some(now + Duration::from_secs(i)));
        }
        assert_eq!(timers.heap.len(), 300);
        timers.set(tuple(1), Some(now));
        assert_eq!(timers.pop_due(now), Some(tuple(1)));
        timers.remove(tuple(299));
        assert_eq!(timers.pop_due(now + Duration::from_secs(1)), None);
        timers.set(tuple(299), Some(now));
        assert_eq!(timers.pop_due(now), Some(tuple(299)));
        let mut previous = now;
        while let Some(&(deadline, tuple)) = timers.heap.first() {
            assert!(deadline >= previous);
            previous = deadline;
            assert_eq!(timers.pop_due(deadline), Some(tuple));
            for (index, &(_, key)) in timers.heap.iter().enumerate() {
                assert_eq!(timers.positions[&key], index);
            }
        }
        assert!(timers.positions.is_empty());
    }
}
