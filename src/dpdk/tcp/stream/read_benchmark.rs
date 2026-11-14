use super::*;
use crate::allocations::count_allocations;
use crate::dpdk::{Mbuf, Mempool, eal, ffi, mempool::DEFAULT_MBUF_DATA_ROOM_SIZE};
use std::{hint::black_box, task::Waker, time::Instant};

const SEGMENT: usize = 1448;

#[test]
#[ignore = "benchmark; run alone in release mode"]
fn benchmark_stream_reads() {
    let cpu = unsafe { libc::sched_getcpu() };
    eal::init(&[
        "stream-read-bench",
        "--no-huge",
        "--no-pci",
        "--no-shconf",
        "--no-telemetry",
        "--lcores",
        &format!("0@{cpu}"),
    ])
    .unwrap();
    {
        let pool = Mempool::create(
            "stream-read-bench",
            2047,
            0,
            DEFAULT_MBUF_DATA_ROOM_SIZE,
            -1,
        )
        .unwrap();
        let available = || unsafe { ffi::rte_mempool_avail_count(pool.as_raw()) };
        let free = available();
        let (mut stream, _commands, inbound, _) = TcpStream::test_stream();
        let mut cx = Context::from_waker(Waker::noop());
        let iterations = 3000;
        println!("mode\tbytes\titerations\tp50_ns\tp95_ns\tallocations_per_mib");
        for size in [64usize, 16 * 1024, 64 * 1024, 1024 * 1024] {
            let expected: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
            let mut output = vec![0; size];
            for name in ["borrowed", "owned_then_copy", "chunk_then_copy"] {
                let borrowed = name == "borrowed";
                let mut samples = Vec::with_capacity(iterations);
                let mut allocations = 0;
                for iteration in 0..129 + iterations {
                    for data in expected.chunks(SEGMENT) {
                        let mut packet = Mbuf::alloc(&pool).unwrap();
                        packet
                            .append(data.len() as u16)
                            .unwrap()
                            .copy_from_slice(data);
                        let message = InboundMessage::Data(Chunk::packet(packet, 0, data.len()));
                        assert!(inbound.push(message).is_ok());
                    }
                    let mut read = || {
                        if borrowed {
                            let mut buf = ReadBuf::new(&mut output);
                            assert!(matches!(
                                Pin::new(&mut stream).poll_read(&mut cx, &mut buf),
                                Poll::Ready(Ok(()))
                            ));
                            assert_eq!(buf.filled().len(), size);
                        } else {
                            let mut offset = 0;
                            while offset < size {
                                let end = if name == "chunk_then_copy" {
                                    let Poll::Ready(Ok(Some(chunk))) =
                                        stream.poll_recv_chunk(&mut cx)
                                    else {
                                        panic!("missing staged mbuf");
                                    };
                                    let end = offset + chunk.len();
                                    output[offset..end].copy_from_slice(&chunk);
                                    end
                                } else {
                                    let Poll::Ready(Ok(Some(chunk))) = stream.poll_recv(&mut cx)
                                    else {
                                        panic!("missing staged mbuf");
                                    };
                                    let end = offset + chunk.len();
                                    output[offset..end].copy_from_slice(&chunk);
                                    end
                                };
                                offset = end;
                            }
                        }
                        black_box(&output);
                    };
                    if iteration < 128 {
                        read();
                    } else if iteration == 128 {
                        let (_, count) = count_allocations(read);
                        allocations = count;
                    } else {
                        let start = Instant::now();
                        read();
                        samples.push(start.elapsed().as_nanos());
                    }
                    assert_eq!(output, expected);
                    assert_eq!(available(), free);
                }
                assert_eq!(
                    allocations,
                    if name == "owned_then_copy" {
                        size.div_ceil(SEGMENT)
                    } else {
                        0
                    }
                );
                samples.sort_unstable();
                let n = samples.len();
                println!(
                    "{name}\t{size}\t{n}\t{}\t{}\t{:.1}",
                    samples[(n - 1) / 2],
                    samples[(n - 1) * 95 / 100],
                    allocations as f64 * (1024 * 1024) as f64 / size as f64
                );
            }
        }
    }
    eal::cleanup();
}
