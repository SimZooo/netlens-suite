use std::{io, net::{IpAddr, Ipv4Addr}};

use pnet::{packet::{arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket}, ethernet::{EtherTypes, MutableEthernetPacket}, ip::IpNextHeaderProtocols, ipv4::{Ipv4Flags, MutableIpv4Packet}, tcp::MutableTcpPacket}, util::MacAddr};

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