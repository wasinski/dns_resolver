use std::net::UdpSocket;

use crate::dns::DnsHeader;
use crate::dns::DnsName;
use crate::dns::DnsPacket;
use crate::dns::DnsQuestion;
use crate::dns::IPv4;
use crate::dns::Reader;
use crate::dns::TYPE_A;

fn build_query(name: &str, record_type: u16, flags: u16) -> Vec<u8> {
    let mut buffer = vec![];
    let header = DnsHeader::new_with_rand_id(flags);
    let question = DnsQuestion::new_for_name(name.to_string(), record_type);
    buffer.extend(header.encode());
    buffer.extend(question.encode());

    buffer
}

#[derive(Debug)]
enum QueryResponse {
    Answer(String),
    Additional(String),
    Authority(String),
}

pub fn send_query(ip_address: &str, domain_name: &str, record_type: u16) -> QueryResponse {
    let dns_query = build_query(domain_name, record_type, 0);

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

    if packet.answers.len() >= 1 {
        QueryResponse::Answer(packet.parse_ip_address())
    } else if packet.additionals.len() >= 1 {
        QueryResponse::Additional(packet.parse_next_name_server_ip())
    } else {
        QueryResponse::Authority(packet.parse_next_name_server_domain())
    }
}

pub fn resolve(domain_name: &str, record_type: u16) -> String {
    let mut name_server = "198.41.0.4".to_string();
    loop {
        let response = send_query(&name_server, domain_name, record_type);

        let next_name_server = match response {
            QueryResponse::Answer(resolved_ip_addr) => return resolved_ip_addr.into(),
            QueryResponse::Additional(next_name_server) => next_name_server.to_owned(),
            QueryResponse::Authority(ns_domain) => resolve(&ns_domain, TYPE_A),
        };

        name_server = next_name_server;
    }
}
