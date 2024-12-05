use std::net::UdpSocket;

use crate::dns::DnsHeader;
use crate::dns::DnsPacket;
use crate::dns::DnsQuestion;
use crate::dns::Reader;

fn build_query(name: String, record_type: u16, flags: u16) -> Vec<u8> {
    let mut buffer = vec![];
    let header = DnsHeader::new_with_rand_id(flags);
    let question = DnsQuestion::new_for_name(name, record_type);
    buffer.extend(header.encode());
    buffer.extend(question.encode());

    buffer
}

// FIX: have a dedicated type for IP address
pub fn send_query(ip_address: &str, domain_name: &str, record_type: u16) -> String {
    // FIX think about providing here string, or having &str as build_query parameter
    let dns_query = build_query(domain_name.to_string(), record_type, 0);

    let socket = UdpSocket::bind("0.0.0.0:0").expect("could not bind socket");
    socket
        .connect(format!("{}:53", ip_address))
        .expect("could not connect to DNS");

    socket
        .send(&dns_query)
        .expect("error on sending query to DNS");

    let mut recv_buffer = [0_u8; 512];
    let recv_size = socket
        .recv(&mut recv_buffer)
        .expect("error on response receiving.");

    let mut reader = Reader::new(&recv_buffer, recv_size);

    let packet = DnsPacket::decode(&mut reader);

    packet.parse_ip_address()
}
