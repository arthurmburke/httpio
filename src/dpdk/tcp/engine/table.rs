//! The engine's connections, in a slab. A received packet finds its
//! connection by hashing its 4-tuple once; from then on the poll loop
//! refers to the connection by [`ConnId`], which is an array index.

use crate::core::hashmap::HashMap;
use crate::dpdk::tcp::tcb::FourTuple;

/// Names one connection for as long as it is tracked. A slot is reused
/// after its connection is removed, under a new generation, so an id kept
/// past that point (in a run queue, or with a queued packet) finds nothing
/// rather than the slot's next occupant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ConnId {
    /// Position in the slab: unique among live connections, and what a
    /// connection's timer is filed under.
    pub index: u32,
    generation: u32,
}

struct Slot<T> {
    generation: u32,
    entry: Option<(FourTuple, T)>,
}

pub(super) struct ConnTable<T> {
    slots: Vec<Slot<T>>,
    free: Vec<u32>,
    index: HashMap<FourTuple, u32>,
}

impl<T> Default for ConnTable<T> {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            index: HashMap::default(),
        }
    }
}

impl<T> ConnTable<T> {
    pub fn contains(&self, tuple: &FourTuple) -> bool {
        self.index.contains_key(tuple)
    }

    /// Tracks a connection. The caller checks first that `tuple` is not
    /// already tracked.
    pub fn insert(&mut self, tuple: FourTuple, value: T) -> (ConnId, &mut T) {
        let index = self.free.pop().unwrap_or_else(|| {
            self.slots.push(Slot {
                generation: 0,
                entry: None,
            });
            (self.slots.len() - 1) as u32
        });
        let previous = self.index.insert(tuple, index);
        debug_assert!(previous.is_none(), "connection already tracked");
        let slot = &mut self.slots[index as usize];
        let id = ConnId {
            index,
            generation: slot.generation,
        };
        (id, &mut slot.entry.insert((tuple, value)).1)
    }

    pub fn get(&self, tuple: &FourTuple) -> Option<&T> {
        let index = *self.index.get(tuple)?;
        self.slots[index as usize].entry.as_ref().map(|e| &e.1)
    }

    /// The one hashed lookup: a connection and the id to use afterwards.
    pub fn get_mut(&mut self, tuple: &FourTuple) -> Option<(ConnId, &mut T)> {
        let index = *self.index.get(tuple)?;
        self.at_mut(index)
    }

    /// The connection `id` names, unless it has been removed since.
    pub fn by_id_mut(&mut self, id: ConnId) -> Option<&mut T> {
        let slot = self.slots.get_mut(id.index as usize)?;
        if slot.generation != id.generation {
            return None;
        }
        slot.entry.as_mut().map(|e| &mut e.1)
    }

    /// The connection now in slot `index`, if any.
    pub fn at_mut(&mut self, index: u32) -> Option<(ConnId, &mut T)> {
        let slot = self.slots.get_mut(index as usize)?;
        let id = ConnId {
            index,
            generation: slot.generation,
        };
        slot.entry.as_mut().map(|e| (id, &mut e.1))
    }

    pub fn id_of(&self, tuple: &FourTuple) -> Option<ConnId> {
        let index = *self.index.get(tuple)?;
        Some(ConnId {
            index,
            generation: self.slots[index as usize].generation,
        })
    }

    pub fn remove(&mut self, id: ConnId) -> Option<T> {
        let slot = self.slots.get_mut(id.index as usize)?;
        if slot.generation != id.generation {
            return None;
        }
        let (tuple, value) = slot.entry.take()?;
        slot.generation = slot.generation.wrapping_add(1);
        self.index.remove(&tuple);
        self.free.push(id.index);
        Some(value)
    }

    #[cfg(test)]
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.slots
            .iter_mut()
            .filter_map(|slot| slot.entry.as_mut().map(|e| &mut e.1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn tuple(port: u16) -> FourTuple {
        FourTuple {
            local_ip: Ipv4Addr::LOCALHOST,
            local_port: port,
            remote_ip: Ipv4Addr::LOCALHOST,
            remote_port: 80,
        }
    }

    #[test]
    fn a_removed_connections_id_does_not_reach_the_slots_next_occupant() {
        let mut table = ConnTable::default();
        let (first, _) = table.insert(tuple(1), "first");
        let (second, _) = table.insert(tuple(2), "second");
        assert_eq!(table.remove(first), Some("first"));
        assert_eq!(table.remove(first), None);
        assert!(!table.contains(&tuple(1)));

        let (reused, _) = table.insert(tuple(3), "third");
        assert_eq!(reused.index, first.index);
        assert_ne!(reused, first);
        assert_eq!(table.by_id_mut(first), None);
        assert_eq!(table.by_id_mut(reused), Some(&mut "third"));
        assert_eq!(table.by_id_mut(second), Some(&mut "second"));
        assert_eq!(table.id_of(&tuple(3)), Some(reused));
        assert_eq!(table.get(&tuple(2)), Some(&"second"));
        assert_eq!(table.get_mut(&tuple(3)), Some((reused, &mut "third")));
        assert_eq!(table.at_mut(second.index), Some((second, &mut "second")));
        assert_eq!(table.values_mut().count(), 2);
    }
}
