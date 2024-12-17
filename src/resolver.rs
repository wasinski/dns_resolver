use std::net::UdpSocket;

use crate::dns::DnsHeader;
use crate::dns::DnsPacket;
use crate::dns::DnsQuestion;
use crate::dns::Reader;
use crate::dns::TYPE_A;
use crate::Result;

fn build_query(name: &str, record_type: u16, flags: u16) -> Vec<u8> {
    let mut buffer = vec![];
    let header = DnsHeader::new_with_rand_id(flags);
    let question = DnsQuestion::new_for_name(name.to_string(), record_type);
    buffer.extend(header.encode());
    buffer.extend(question.encode());

    buffer
}

#[derive(Debug)]
pub enum QueryResponse {
    Answer(String),
    Additional(String),
    Authority(String),
}

pub fn send_query(ip_address: &str, domain_name: &str, record_type: u16) -> Result<QueryResponse> {
    let dns_query = build_query(domain_name, record_type, 0);

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(format!("{}:53", ip_address))?;

    socket.send(&dns_query)?;

    let mut recv_buffer = [0_u8; 512];
    let recv_size = socket.recv(&mut recv_buffer)?;

    let mut reader = Reader::new(&recv_buffer, recv_size);

    let packet = DnsPacket::decode(&mut reader);

    let resp = if !packet.answers.is_empty() {
        QueryResponse::Answer(packet.parse_ip_address()?)
    } else if !packet.additionals.is_empty() {
        QueryResponse::Additional(packet.parse_next_name_server_ip()?)
    } else {
        QueryResponse::Authority(packet.parse_next_name_server_domain()?)
    };

    Ok(resp)
}

pub fn resolve(domain_name: &str, record_type: u16) -> Result<String> {
    let mut name_server = "198.41.0.4".to_string();
    loop {
        let response = send_query(&name_server, domain_name, record_type)?;

        let next_name_server = match response {
            QueryResponse::Answer(resolved_ip_addr) => return Ok(resolved_ip_addr),
            QueryResponse::Additional(next_name_server) => next_name_server.to_owned(),
            QueryResponse::Authority(ns_domain) => resolve(&ns_domain, TYPE_A)?,
        };

        name_server = next_name_server;
    }
}
