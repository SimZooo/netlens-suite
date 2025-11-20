use std::{net::{IpAddr, Ipv4Addr}, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}, thread::{self, sleep}, time::{Duration, Instant}};
use serde_json::json;
use threadpool::ThreadPool;

use clap::Parser;
use pnet::{datalink::Channel::Ethernet, ipnetwork::Ipv4Network, packet::{Packet, arp::{ArpOperations, ArpPacket}, ethernet::{EtherTypes, EthernetPacket}}, util::MacAddr};

use common::*;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    network: String,
    #[arg(short, long)]
    threads: Option<usize>,
    #[arg(short, long)]
    json: bool
}

fn main() {
    let start_time = Instant::now();
    let args = Args::parse();
    let threads = args.threads.unwrap_or(30);
    let finished_sending = Arc::new(AtomicBool::new(false));
    let finished_clone = finished_sending.clone();

    let cidr = args.network.parse::<Ipv4Network>().unwrap_or_else(|_| fatal("Make sure network exists"));
    let interfaces = pnet::datalink::interfaces();

    let replies = Arc::new(Mutex::new(Vec::<(Ipv4Addr, String, String)>::new()));
    let replies_clone = replies.clone();

    // Find interface with specified network address
    let interface = interfaces.iter().find(|itf| itf.ips.iter().any(|ip| {
        match ip.ip() {
            IpAddr::V4(ip) => cidr.contains(ip),
            _ => false
        }
    })).unwrap_or_else(|| fatal("Make sure network exists"));

    // Create transmitter and receiver
    let (mut tx, mut rx) = match pnet::datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => fatal("Unhandled interface type"),
        Err(e) => fatal(format!("Failed to create channel to interface: {e}"))
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
                                        if !map.contains(&(arp.get_sender_proto_addr(), eth.get_source().to_string(), eth.get_ethertype().to_string())) {
                                            map.push((arp.get_sender_proto_addr(), eth.get_source().to_string(), arp.get_protocol_type().to_string()));
                                        }
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
    
    if !args.json {
        println!("Scanning network: {} with {} threads", args.network, threads);
    }
    // Iterate through all hosts
    for ip in cidr.iter().skip(1).take((cidr.size() - 2) as usize) {
        let source_ip = interface.ips.iter().filter_map(|ip| {
            if let IpAddr::V4(ip) = ip.ip() {
                Some(ip)
            } else {
                None
            }
        }).next().unwrap_or_else(|| fatal("Make sure network exists"));

        let buffer = build_ping(interface.mac.unwrap_or_else(|| fatal("Make sure network exists")), source_ip, ip);
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

    receiver_handle.join().unwrap_or_else(|_| fatal("Failed to join receiver handle"));
    pool.join();
    let replies = replies.lock().unwrap_or_else(|_| fatal("Failed to lock replies"));
    if args.json {
        let replies_json = json!(*replies);
        println!("{}", replies_json);
        return;
    } else {
        for ip in replies.iter() {
            println!("Host: {} is up! Mac: {}", ip.0, ip.1)
        }
    }
    let end_time = Instant::now();

    println!("{} Hosts found. Operation took: {}", replies.len(), (end_time - start_time).as_secs_f32());
}