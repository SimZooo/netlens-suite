use std::{io, net::{IpAddr, Ipv4Addr}, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}, thread::{self, sleep}, time::{Duration, Instant}};
use threadpool::ThreadPool;

use clap::Parser;
use pnet::{datalink::{Channel::Ethernet}, ipnetwork::{Ipv4Network}, packet::{Packet, arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket}, ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket}}, util::MacAddr};

fn build_ping(source_mac: MacAddr, source: Ipv4Addr, dest: Ipv4Addr) -> io::Result<Vec<u8>> {
    let mut buffer= vec![0u8; 42];
    let eth_packet = MutableEthernetPacket::new(&mut buffer[..]);

    if let Some(mut eth_packet) = eth_packet {
        eth_packet.set_source(source_mac);
        eth_packet.set_destination(MacAddr::broadcast());
        eth_packet.set_ethertype(EtherTypes::Arp);

        let arp_packet = MutableArpPacket::new(&mut buffer[14..]);
        if let Some(_) = arp_packet {
            match MutableArpPacket::new(&mut buffer[14..]) {
                Some(mut arp_pkt) => {
                    arp_pkt.set_hardware_type(ArpHardwareTypes::Ethernet);
                    arp_pkt.set_protocol_type(EtherTypes::Ipv4);
                    arp_pkt.set_hw_addr_len(6);
                    arp_pkt.set_proto_addr_len(4);
                    arp_pkt.set_operation(ArpOperations::Request);
                    arp_pkt.set_sender_hw_addr(source_mac);
                    arp_pkt.set_sender_proto_addr(source);
                    arp_pkt.set_target_hw_addr(MacAddr::zero());
                    arp_pkt.set_target_proto_addr(dest);
                },
                None => {
                    eprintln!("Failed to build ARP packet");
                    return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, format!("Failed to ping address: {}", dest.to_string())));
                }
            };

        } else {
            return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, format!("Failed to ping address: {}", dest.to_string())));
        }
    } else {
        return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, format!("Failed to ping address: {}", dest.to_string())));
    }

    Ok(buffer)
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    network: String,

    #[arg(short, long, default_value_t = 1)]
    count: u8,

    #[arg(short, long)]
    threads: Option<usize>
}

fn main() {
    let start_time = Instant::now();
    let args = Args::parse();
    let threads = args.threads.unwrap_or(30);
    let finished_sending = Arc::new(AtomicBool::new(false));
    let finished_clone = finished_sending.clone();

    let cidr = args.network.parse::<Ipv4Network>().expect("Make sure network exists");
    let interfaces = pnet::datalink::interfaces();

    let replies = Arc::new(Mutex::new(Vec::<Ipv4Addr>::new()));
    let replies_clone = replies.clone();

    // Find interface with specified network address
    let interface = interfaces.iter().find(|itf| itf.ips.iter().any(|ip| {
        match ip.ip() {
            IpAddr::V4(ip) => cidr.contains(ip),
            _ => false
        }
    })).expect("Make sure network exists");

    // Create transmitter and receiver
    let (mut tx, mut rx) = match pnet::datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(_) => panic!("Failed to create channel to interface")
    };

    let pool = Arc::new(ThreadPool::new(threads));
    let pool_clone = pool.clone();

    // Start receiving packets
    let timeout = 5;
    let receiver_handle = thread::spawn(move || {
        while !finished_clone.clone().load(Ordering::Acquire) {
            sleep(Duration::from_millis(1));
        }
        
        let sleep_time = Instant::now() + Duration::from_secs(timeout);

        while Instant::now() < sleep_time {
            match rx.next() {
                Ok(packet) => {
                    let reply_clone = replies_clone.clone();
                    let packet_clone = packet.to_vec();

                    pool_clone.execute(move|| {
                        if packet_clone.len() < 42 { return; }

                        if let Some(eth) = EthernetPacket::new(&packet_clone) {
                            if eth.get_ethertype() != EtherTypes::Arp { return; }

                            if let Some(arp) = ArpPacket::new(eth.payload()) {
                                if arp.get_operation() != ArpOperations::Reply { return; }
                                match reply_clone.lock() {
                                    Ok(mut map) => {
                                        map.push(arp.get_sender_proto_addr());
                                    },
                                    Err(e) => { eprintln!("Failed to lock replies vec: {e}"); return; }
                                };
                            }
                        }
                    })
                },
                Err(_) => {}
            }
        }
    });
    
    println!("Scanning network: {} with {} threads", args.network, threads);
    // Iterate through all hosts
    for ip in cidr.iter().skip(1).take((cidr.size() - 2) as usize) {
        let source_ip = interface.ips.iter().filter_map(|ip| {
            if let IpAddr::V4(ip) = ip.ip() {
                Some(ip)
            } else {
                None
            }
        }).next().expect("Make sure network exists");

        let buffer = build_ping(interface.mac.expect("Make sure network exists"), source_ip, ip);
        if let Ok(packet) = buffer {
            if let Some(Err(e)) = tx.send_to(&packet, None) {
                eprintln!("Failed to ping host: {}, err: {}", ip.to_string(), e);
                continue;
            }
        } else {
            eprintln!("Failed to ping host: {}", ip.to_string());
            continue;
        }
    }

    finished_sending.store(true, Ordering::Release);

    receiver_handle.join().expect("Failed to join receiver handle");
    pool.join();
    let replies = replies.lock().expect("Failed to lock replies");
    for ip in replies.iter() {
        println!("Host: {ip} is up!")
    }
    let end_time = Instant::now();
    println!("{} Hosts found. Operation took: {}", replies.len(), (end_time - start_time).as_secs_f32());
}