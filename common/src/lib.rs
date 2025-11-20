use std::{io::{self, Read, Write}, net::{IpAddr, Ipv4Addr, TcpStream}, process::exit, time::Duration};

use log::debug;
use pnet::{datalink::{self, NetworkInterface}, packet::{arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket}, ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket}, ip::IpNextHeaderProtocols, ipv4::{Ipv4Flags, MutableIpv4Packet}, tcp::MutableTcpPacket}, util::MacAddr};
use pnet::packet::Packet;
use pnet::datalink::Channel::Ethernet;

pub fn build_tcp_packet(
    src_port: u16, 
    dst_port: u16, 
    flags: u8, 
    seq: u32, 
    window: u16, 
    src_ip: Ipv4Addr, 
    dest_ip: Ipv4Addr
) -> Vec<u8> {
    let mut buf = vec![0u8; 40];
    let (ip_buf, tcp_buf) = buf.split_at_mut(20);

    // Build IPv4 header
    let mut packet = MutableIpv4Packet::new(ip_buf).unwrap();
    packet.set_version(4);
    packet.set_header_length(5);
    packet.set_total_length(40);
    packet.set_ttl(64);
    packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    packet.set_source(src_ip);
    packet.set_destination(dest_ip);
    packet.set_flags(Ipv4Flags::DontFragment);
    packet.set_identification(0);

    // Build TCP header in buf[20..40]
    let mut tcp_packet = MutableTcpPacket::new(tcp_buf).unwrap();
    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    tcp_packet.set_sequence(seq);
    tcp_packet.set_acknowledgement(0);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_flags(flags);
    tcp_packet.set_window(window);
    tcp_packet.set_urgent_ptr(0);

    // TCP checksum
    let tcp_checksum = pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_ip, &dest_ip);
    tcp_packet.set_checksum(tcp_checksum);

    // IPv4 checksum
    let ipv4_checksum = pnet::packet::ipv4::checksum(&packet.to_immutable());
    packet.set_checksum(ipv4_checksum);

    buf
}

pub fn build_ping(source_mac: MacAddr, source: Ipv4Addr, dest: Ipv4Addr) -> io::Result<Vec<u8>> {
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

pub fn get_interface_ip(name: &str) -> Option<Ipv4Addr> {
    for iface in pnet::datalink::interfaces() {
        if iface.name == name {
            for ip in iface.ips {
                if let IpAddr::V4(ipv4) = ip.ip() {
                    return Some(ipv4);
                }
            }
        }
    }
    None
}

pub fn fatal(msg: impl AsRef<str>) -> ! {
    eprintln!("Error: {}", msg.as_ref());
    exit(1)
}

pub fn grab_banner(addr: Ipv4Addr, port: u16) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(format!("{}:{}", addr, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;

    stream.write_all(b"\n")?;

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    let tmp = String::from_utf8_lossy(&buf[..n]).to_string();
    let banner_line = tmp.split_ascii_whitespace().next().unwrap_or_else(|| {
        return ""
    });

    Ok(banner_line.to_string())
}

pub fn interface_from_ip(network_address: String) -> Option<NetworkInterface> {
    let interfaces = pnet::datalink::interfaces();
    let target_network: IpAddr = network_address.parse().unwrap_or_else(|_| fatal("Failed to parse network address, make sure the input is correct"));
    let interface = interfaces.iter().find(|iface| {
        iface.ips.iter().any(|network| {
            network.ip() == target_network
        })
    });

    interface.cloned()
}

pub fn get_mac_for_ip(target_ip: Ipv4Addr) -> Option<MacAddr> {
    // Choose interface (change name if needed)
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == "wlan0" || iface.name == "eth0")
        .expect("No usable interface");

    let source_mac = interface.mac?;
    let source_ip = interface.ips
        .iter()
        .find_map(|ip| match ip.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        })?;

    // Create datalink channel (raw packet send/receive)
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Failed to open datalink channel"),
    };

    // === Build ARP Request ===
    let mut ethernet_buf = [0u8; 42];
    {
        let mut eth_packet = MutableEthernetPacket::new(&mut ethernet_buf).unwrap();

        eth_packet.set_destination(pnet::datalink::MacAddr::broadcast());
        eth_packet.set_source(source_mac);
        eth_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_buf = [0u8; 28];
        {
            let mut arp_packet = MutableArpPacket::new(&mut arp_buf).unwrap();
            arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_packet.set_protocol_type(EtherTypes::Ipv4);
            arp_packet.set_hw_addr_len(6);
            arp_packet.set_proto_addr_len(4);
            arp_packet.set_operation(ArpOperations::Request);
            arp_packet.set_sender_hw_addr(source_mac);
            arp_packet.set_sender_proto_addr(source_ip);
            arp_packet.set_target_hw_addr(pnet::datalink::MacAddr::zero());
            arp_packet.set_target_proto_addr(target_ip);
        }

        eth_packet.set_payload(&arp_buf);
    }

    // Send ARP request
    tx.send_to(&ethernet_buf, None).unwrap();

    // === Wait for ARP reply ===
    loop {
        if let Ok(packet) = rx.next() {
            if let Some(eth) = EthernetPacket::new(packet) {
                if eth.get_ethertype() == EtherTypes::Arp {
                    if let Some(arp) = ArpPacket::new(eth.payload()) {
                        if arp.get_operation() == ArpOperations::Reply &&
                           arp.get_sender_proto_addr() == target_ip
                        {
                            return Some(arp.get_sender_hw_addr());
                        }
                    }
                }
            }
        }
    }
}