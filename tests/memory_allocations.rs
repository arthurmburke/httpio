#[path = "support/allocations.rs"]
mod allocations;
#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;
use allocations::count_allocations;
use bytes::Bytes;
use httpio::http::codec::{self, EncodedBody, Raw};

#[test]
fn raw_codec_moves_bytes_without_boxing() {
    let bytes = Bytes::from_static(b"raw payload");
    let ptr = bytes.as_ptr();
    let (encoded, count) = count_allocations(|| codec::encode(None, Raw(bytes)).unwrap());
    assert_eq!(count, 0);
    let EncodedBody::Full(encoded) = encoded else {
        panic!("expected full body")
    };
    assert_eq!(encoded.as_ptr(), ptr);
    let (decoded, count) = count_allocations(|| codec::decode::<Raw>(None, encoded).unwrap());
    assert_eq!(count, 0);
    assert_eq!(decoded.0.as_ptr(), ptr);
}

#[cfg(dpdk)]
#[test]
fn common_segments_retain_slices_without_allocating_or_copying() {
    use httpio::dpdk::tcp::tx_queue::SendBuffer;
    let a = Bytes::from_static(b"abc");
    let b = Bytes::from_static(b"defghi");
    let mut queue = SendBuffer::default();
    queue.push(a.clone());
    queue.push(b.clone());
    let (payload, count) = count_allocations(|| queue.take(7));
    assert_eq!(count, 0);
    let mut chunks = payload.chunks();
    assert_eq!(chunks.next().unwrap().as_ptr(), a.as_ptr());
    assert_eq!(chunks.next().unwrap().as_ptr(), b.as_ptr());
    assert!(chunks.next().is_none());
    let (retransmit, count) = count_allocations(|| payload.clone());
    assert_eq!(count, 0);
    assert!(retransmit == b"abcdefg"[..]);
    assert_eq!(queue.len(), 2);
    assert!(queue.take(10) == b"hi"[..]);
}

#[cfg(dpdk)]
#[test]
fn fragmented_segments_keep_packet_size_and_share_retransmit_storage() {
    use httpio::dpdk::tcp::tx_queue::SendBuffer;
    let mut queue = SendBuffer::default();
    for _ in 0..100 {
        queue.push(Bytes::from_static(b"ab"));
    }
    let payload = queue.take(199);
    assert_eq!(payload.len(), 199);
    assert_eq!(payload.chunks().count(), 100);
    let (retransmit, count) = count_allocations(|| payload.clone());
    assert_eq!(count, 0);
    for (a, b) in payload.chunks().zip(retransmit.chunks()) {
        assert_eq!(a.as_ptr(), b.as_ptr());
    }
    let mut wire = [0; 199];
    retransmit.copy_to(&mut wire);
    assert!(
        wire.iter()
            .enumerate()
            .all(|(i, &b)| b == if i % 2 == 0 { b'a' } else { b'b' })
    );
    assert!(queue.take(1) == b"b"[..]);
}
