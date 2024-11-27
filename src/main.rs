use rand::Rng;
use std::env;
use std::io::Read;
use std::net::UdpSocket;

#[derive(Debug)]
struct DnsHeader {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

impl DnsHeader {
    fn new_with_rand_id() -> Self {
        let mut rng = rand::thread_rng();

        let id: u16 = rng.gen();
        let num_questions = 1;
        let flags = 1 << 8;

        Self {
            id,
            flags,
            num_questions,
            num_answers: 0,
            num_authorities: 0,
            num_additionals: 0,
        }
    }

    fn encode(self) -> Vec<u8> {
        let mut buffer = vec![];

        buffer.extend(self.id.to_be_bytes());
        buffer.extend(self.flags.to_be_bytes());
        buffer.extend(self.num_questions.to_be_bytes());
        buffer.extend(self.num_answers.to_be_bytes());
        buffer.extend(self.num_authorities.to_be_bytes());
        buffer.extend(self.num_additionals.to_be_bytes());

        buffer
    }
}

#[derive(Debug)]
struct DnsName(Vec<u8>);

impl DnsName {
    fn encoded_from_string(s: &str) -> Self {
        assert!(
            s.is_ascii(),
            "dns name must not contain non-ascii characters"
        );

        let mut encoded = vec![];
        for label in s.split(".") {
            assert!(
                0 < label.len() && label.len() <= 64,
                "dns label not in len range"
            );
            encoded.push(0);
            encoded.push(label.len() as u8);
            encoded.extend_from_slice(label.as_bytes());
        }
        encoded.push(0);

        Self(encoded)
    }
}

struct DnsQuestion {
    name: DnsName,
    qtype: u16,
    qclass: u16,
}

impl DnsQuestion {
    fn new_for_name(name: &str) -> Self {
        let name = DnsName::encoded_from_string(name);

        Self {
            name,
            qtype: 1,  // TYPE_A IPv4
            qclass: 1, // CLASS_IN Internet
        }
    }

    fn encode(self) -> Vec<u8> {
        let mut buffer = vec![];

        buffer.extend(self.name.0);
        buffer.extend(self.qtype.to_be_bytes());
        buffer.extend(self.qclass.to_be_bytes());

        buffer
    }
}

fn build_query(name: &str) -> Vec<u8> {
    let mut buffer = vec![];
    let header = DnsHeader::new_with_rand_id();
    let question = DnsQuestion::new_for_name(name);
    buffer.extend(header.encode());
    buffer.extend(question.encode());

    buffer
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let domain_name = match &args.as_slice() {
        &[_, domain_name] => domain_name,
        _ => panic!("improper arguments"),
    };

    let dns_query = build_query(&domain_name);
    println!(
        "DNS Query (hex): {}",
        dns_query
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<_>>()
            .join(" ")
    );
    // let socket = UdpSocket::bind("0.0.0.0:0").expect("could not bind socket");
    // socket
    //     .connect("8.8.8.8:53")
    //     .expect("could not connect to DNS");

    // socket
    //     .send(&dns_query)
    //     .expect("error on sending query to DNS");

    // let mut recv_buffer = [0 as u8; 512];
    // let recv_size = socket
    //     .recv(&mut recv_buffer)
    //     .expect("error on response receiving.");

    // dbg!(&recv_buffer[..recv_size]);
}
