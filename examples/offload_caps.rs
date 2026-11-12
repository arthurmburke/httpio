//! Inspect a PMD's negotiated offloads without opening a TCP connection.
//! cargo run --release --example offload_caps -- --no-huge --no-pci --vdev=net_ring0
#[cfg(dpdk)]
fn main() {
    use httpio::dpdk::{EthPort, Mempool, eal, mempool::DEFAULT_MBUF_DATA_ROOM_SIZE};
    let args: Vec<String> = std::env::args().collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    eal::init(&refs).expect("EAL initialization");
    {
        let pool = Mempool::create("offload-caps", 4095, 0, DEFAULT_MBUF_DATA_ROOM_SIZE, -1)
            .expect("pool");
        for id in 0..EthPort::count_avail() {
            let port = EthPort::init(id, &pool, 128, 128, 1500, 0).expect("port initialization");
            println!("port {id}: {:?}", port.offloads());
        }
    }
    eal::cleanup();
}
#[cfg(not(dpdk))]
fn main() {
    eprintln!("Run this example in the DPDK devcontainer.");
}
