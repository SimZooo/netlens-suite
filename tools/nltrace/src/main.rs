use std::time::{SystemTime, UNIX_EPOCH};

use clap::{ArgGroup, Parser};
use common::fatal;
use pnet::{datalink::Channel::Ethernet, packet::{ethernet::EthernetPacket, ipv4::Ipv4Packet}};
use serde_json::json;
use serde::Serialize;
use pnet::packet::Packet;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
#[command(group(ArgGroup::new("network_info").required(true)))]
struct Args {
    #[arg(short, long, group = "network_info")]
    address: Option<String>,
    #[arg(short, long, group = "network_info")]
    interface: Option<String>,
    #[arg(short, long)]
    threads: Option<usize>,
}

#[derive(Debug, Serialize, Default)]
pub struct PacketRes {
    time_epoch: u64,
    packet_type: String,
    mac_source: String,
    mac_destination: String,
    ip_source: String,
    ip_destination: String,
}

fn handle_packet(buf: &[u8]) {
    let mut packet = PacketRes::default();
    packet.time_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    if let Some(eth_packet) = EthernetPacket::new(buf) {
        packet.mac_source = eth_packet.get_source().to_string();
        packet.mac_destination = eth_packet.get_destination().to_string();

        if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
            packet.packet_type = ip_packet.get_next_level_protocol().to_string();
            packet.ip_source = ip_packet.get_source().to_string();
            packet.ip_destination = ip_packet.get_destination().to_string();

            let json_packet = json!(packet);
            println!("{}", json_packet);
        }
    }
}

fn main() {
    let args = Args::parse();
    let interfaces = pnet::datalink::interfaces();
    
    let interface = match args.address {
        Some(address) => {
            common::interface_from_ip(address)
        },
        None => {
            interfaces.iter().find(|iface| iface.name == args.interface.clone().unwrap_or_else(|| fatal("Either address or interface must be specified"))).cloned()
        }
    }.unwrap_or_else(|| fatal("Interface/address specified does not exist"));

    let (_, mut rx) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => fatal("Unsupported interface type"),
        Err(e) => {fatal(format!("Something went wrong {e}"))}
    };

    loop {
        match rx.next() {
            Ok(buf) => {
                handle_packet(buf);
            },
            Err(_) => {
            }
        }
    }
}