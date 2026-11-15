//! Which receive queue gets which connection, on a port with several.
//!
//! Each worker lcore owns one queue pair and its own `TcpEngine`, and no
//! connection state is shared between them. That only works if every
//! segment of a connection arrives on the queue of the worker that owns it.
//! For connections this host opens, the stack chooses the local port, so
//! the port is what decides the queue: the ephemeral range is divided
//! among the queues by the low bits of the port number, and the NIC is
//! given one `rte_flow` rule per bit pattern (see
//! [`EthPort::init_queues`](super::EthPort::init_queues)). The application
//! never sees any of this: it passes a local port to a
//! [`WorkerHandle`](super::tcp::worker::WorkerHandle) as it always has,
//! and the handle gives the connection to the worker that port leads to.
//! A caller that takes ports in sequence spreads its connections evenly.
//!
//! Low bits rather than contiguous ranges because a masked match on the
//! TCP destination port is what flow rules can express on every driver
//! that has them; a range match (`last`) is not.
//!
//! Segments to any other port (a listening port, for instance) match no
//! rule and are spread by RSS, which keeps each such connection on one
//! queue too: the worker that receives its SYN owns it.

/// First port of the ephemeral range local ports are taken from.
pub const EPHEMERAL_FIRST: u16 = 49152;
/// Last (inclusive) port of the ephemeral range.
pub const EPHEMERAL_LAST: u16 = 65535;
/// Most queues a port can be divided among.
pub const MAX_QUEUES: u16 = 64;

/// One flow rule: TCP segments whose destination port, under `mask`,
/// equals `dst_port` go to `queue`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowRule {
    pub dst_port: u16,
    pub mask: u16,
    pub queue: u16,
}

/// The division of the ephemeral port range among a port's queues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortSteering {
    queues: u16,
}

impl PortSteering {
    /// # Panics
    /// If `queues` is zero or more than [`MAX_QUEUES`].
    pub fn new(queues: u16) -> Self {
        assert!(
            (1..=MAX_QUEUES).contains(&queues),
            "a port has 1..={MAX_QUEUES} queues, not {queues}"
        );
        Self { queues }
    }

    /// One queue: every port leads to it and no rules are needed.
    pub fn single() -> Self {
        Self { queues: 1 }
    }

    pub fn queues(&self) -> u16 {
        self.queues
    }

    /// Distinct low-bit patterns of a port: the queue count rounded up to
    /// a power of two, so a pattern is a mask. When that is more than the
    /// queue count, the surplus patterns wrap around onto the first queues.
    fn patterns(&self) -> u16 {
        self.queues.next_power_of_two()
    }

    /// The queue that receives segments addressed to local `port`, or
    /// `None` for a port outside the ephemeral range, which no rule covers.
    pub fn queue_of(&self, port: u16) -> Option<u16> {
        (port >= EPHEMERAL_FIRST).then(|| (port & (self.patterns() - 1)) % self.queues)
    }

    /// The rules that make the NIC agree with [`queue_of`](Self::queue_of).
    /// None for a single queue.
    pub fn rules(&self) -> impl Iterator<Item = FlowRule> {
        let (patterns, queues) = (self.patterns(), self.queues);
        // The ephemeral range is exactly the ports with the top two bits
        // set, so it is itself a masked match.
        (0..if queues == 1 { 0 } else { patterns }).map(move |pattern| FlowRule {
            dst_port: EPHEMERAL_FIRST | pattern,
            mask: EPHEMERAL_FIRST | (patterns - 1),
            queue: pattern % queues,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a NIC programmed with `rules` does with a destination port.
    fn nic_queue(rules: &[FlowRule], port: u16) -> Option<u16> {
        let mut hits = rules
            .iter()
            .filter(|rule| port & rule.mask == rule.dst_port);
        let hit = hits.next().map(|rule| rule.queue);
        assert!(hits.next().is_none(), "port {port} matches two rules");
        hit
    }

    #[test]
    fn the_rules_send_every_port_where_queue_of_says() {
        for queues in 1..=MAX_QUEUES {
            let steering = PortSteering::new(queues);
            let rules: Vec<_> = steering.rules().collect();
            assert!(rules.iter().all(|rule| rule.queue < queues));
            if queues == 1 {
                assert!(rules.is_empty());
                assert_eq!(steering.queue_of(EPHEMERAL_FIRST), Some(0));
                assert_eq!(steering.queue_of(80), None);
                continue;
            }
            assert_eq!(rules.len(), usize::from(queues.next_power_of_two()));
            for port in 0..=u16::MAX {
                assert_eq!(
                    nic_queue(&rules, port),
                    steering.queue_of(port),
                    "queues={queues} port={port}"
                );
            }
        }
    }

    #[test]
    fn every_queue_gets_ports_and_only_its_own() {
        for queues in [1, 2, 3, 5, 8, 12, 64] {
            let steering = PortSteering::new(queues);
            let mut owned = vec![0usize; usize::from(queues)];
            for port in EPHEMERAL_FIRST..=EPHEMERAL_LAST {
                owned[usize::from(steering.queue_of(port).unwrap())] += 1;
            }
            let total = usize::from(EPHEMERAL_LAST - EPHEMERAL_FIRST) + 1;
            assert_eq!(owned.iter().sum::<usize>(), total);
            // No queue is short of ports even when the count is not a
            // power of two: the smallest share is half the largest.
            let (least, most) = (owned.iter().min().unwrap(), owned.iter().max().unwrap());
            assert!(*least >= total / usize::from(queues) / 2 && least * 2 >= *most);
        }
    }
}
