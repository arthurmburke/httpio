#![cfg(dpdk)]
#[path = "support/allocations.rs"]
mod allocations;
#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;
use allocations::count_allocations;
use bytes::Bytes;
use httpio::dpdk::tcp::{rto::RetransmitQueue, seq::Seq};
use httpio::dpdk::{DmaBuffer, EthPort, Mbuf, Mempool, eal, ffi};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Counted {
    data: DmaBuffer,
    drops: Arc<AtomicUsize>,
}
impl AsRef<[u8]> for Counted {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}
impl Drop for Counted {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn external_payload_lives_through_ack_driver_clone_and_cross_thread_completion() {
    let cpu = unsafe { libc::sched_getcpu() };
    eal::init(&[
        "external-test",
        "--no-huge",
        "--no-pci",
        "--no-shconf",
        "--no-telemetry",
        "--lcores",
        &format!("0@{cpu}"),
        "--vdev=net_ring0",
    ])
    .unwrap();
    {
        let pool = Mempool::create("external-test", 255, 0, 2176, -1).unwrap();
        let port = EthPort::init(0, &pool, 128, 128, 1500, 0).unwrap();
        let available = || unsafe { ffi::rte_mempool_avail_count(pool.as_raw()) };
        let baseline = available();
        let drops = Arc::new(AtomicUsize::new(0));
        let mut dma = DmaBuffer::new(256).unwrap();
        for (i, b) in dma.as_mut_slice().iter_mut().enumerate() {
            *b = i as u8;
        }
        let bytes = Bytes::from_owner(Counted {
            data: dma,
            drops: drops.clone(),
        });
        let expected = bytes.as_ptr();
        let (packet, allocs) =
            count_allocations(|| Mbuf::from_external_bytes(&pool, bytes.clone()).unwrap());
        assert_eq!(
            allocs, 0,
            "attachment metadata must come from the DPDK pool"
        );
        assert_eq!(packet.data().as_ptr(), expected);
        assert_eq!(packet.pkt_len(), 256);
        assert_eq!(
            available(),
            baseline - 2,
            "attachment plus persistent owner record"
        );
        let mut queue = RetransmitQueue::default();
        queue.push(
            Seq::new(100),
            bytes.clone(),
            false,
            false,
            std::time::Instant::now(),
        );
        drop(bytes);
        let clone =
            unsafe { Mbuf::from_raw(ffi::rte_pktmbuf_clone(packet.as_raw(), pool.as_raw())) };
        drop(packet);
        queue.ack_up_to(Seq::new(356), std::time::Instant::now());
        assert_eq!(
            drops.load(Ordering::SeqCst),
            0,
            "ACK must not release NIC-held storage"
        );
        // Reusing the original attachment's mbuf must not overwrite clone metadata.
        let mut scratch = Mbuf::alloc(&pool).unwrap();
        scratch.append(128).unwrap().fill(0xff);
        assert_eq!(clone.data().as_ptr(), expected);
        assert_eq!(clone.data(), (0..256).map(|i| i as u8).collect::<Vec<_>>());
        std::thread::spawn(move || drop(clone)).join().unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(scratch);
        drop(queue);
        assert_eq!(available(), baseline);

        let bytes = DmaBuffer::new(64).unwrap().freeze();
        let mut packet = Mbuf::from_external_bytes(&pool, bytes.clone()).unwrap();
        assert!(packet.append(1).is_none());
        assert!(packet.prepend(1).is_none());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                packet.data_mut();
            }))
            .is_err()
        );
        packet.reset();
        packet.append(16).unwrap().fill(7);
        assert_eq!(
            &bytes[..],
            &[0; 64],
            "mutable packet reuse must detach the immutable owner"
        );
        drop(packet);
        assert_eq!(available(), baseline);
        assert!(Mbuf::from_external_bytes(&pool, Bytes::from(vec![1; 64])).is_none());
        assert_eq!(available(), baseline);

        // Transmit ownership also survives the ethdev boundary; the loopback
        // driver returns the same external payload with no copying.
        let mut frame = Mbuf::alloc(&pool).unwrap();
        frame.append(14).unwrap().fill(0);
        frame
            .chain(Mbuf::from_external_bytes(&pool, bytes.clone()).unwrap())
            .ok()
            .unwrap();
        let mut batch = vec![frame];
        port.tx_burst_in_place(&mut batch);
        assert!(batch.is_empty());
        let mut received = port.rx_packets(64);
        let frame = received.next().unwrap();
        assert_eq!(frame.segments().nth(1).unwrap().as_ptr(), bytes.as_ptr());
        drop(frame);
        drop(received);
        assert_eq!(available(), baseline);

        // Failure to allocate the record releases the attachment mbuf immediately.
        let mut held = Vec::new();
        while available() > 1 {
            held.push(Mbuf::alloc(&pool).unwrap());
        }
        assert!(Mbuf::from_external_bytes(&pool, bytes.clone()).is_none());
        assert_eq!(available(), 1);
        drop(held);
        drop(bytes);
        assert_eq!(available(), baseline);
    }
    eal::cleanup();
}
