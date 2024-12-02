use rand::Rng;
use std::env;
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

    fn decode(r: &mut Reader) -> Self {
        let b = r.read(12);
        Self {
            id: u16::from_be_bytes(b[0..2].try_into().unwrap()),
            flags: u16::from_be_bytes(b[2..4].try_into().unwrap()),
            num_questions: u16::from_be_bytes(b[4..6].try_into().unwrap()),
            num_answers: u16::from_be_bytes(b[6..8].try_into().unwrap()),
            num_authorities: u16::from_be_bytes(b[8..10].try_into().unwrap()),
            num_additionals: u16::from_be_bytes(b[10..12].try_into().unwrap()),
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

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    len: usize,
}

impl Reader<'_> {
    fn new<'a>(buf: &'a [u8], len: usize) -> Reader<'a> {
        return Reader { buf, pos: 0, len };
    }

    fn read(&mut self, len: usize) -> &[u8] {
        assert!(
            self.pos + len < self.len,
            "limit len: {}, pos: {}, new pos: {}",
            self.len,
            self.pos,
            self.pos + len
        );
        let r = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        dbg!(&r);
        r
    }

    fn seek(&mut self, pos: usize) {
        assert!(pos < self.len);
        self.len = pos;
    }

    fn tell(&self) -> usize {
        self.pos
    }
}

#[derive(Debug)]
struct DnsName(String);

impl DnsName {
    fn new(s: &str) -> Self {
        assert!(
            s.is_ascii(),
            "dns name must not contain non-ascii characters"
        );
        Self(s.to_string())
    }

    fn decode(r: &mut Reader) -> Self {
        Self::new(&Self::decode_name(r))
    }
    fn decode_name(r: &mut Reader) -> String {
        let mut parts: Vec<String> = vec![];
        loop {
            let len = r.read(1)[0];
            if len == 0 {
                break;
            }
            if (len & 0b1100_0000) != 0 {
                parts.push(DnsName::decode_compressed_name(len, r));
                break;
            } else {
                let part = String::from_utf8(r.read(len as usize).to_vec()).unwrap();
                parts.push(part);
            };
        }

        parts.join(".")
    }

    fn decode_compressed_name(len: u8, r: &mut Reader) -> String {
        let pointer_bytes = [(len & 0b0011_1111), r.read(1)[0]];
        let pointer = u16::from_be_bytes(pointer_bytes);

        let current_pos = r.tell();
        r.seek(pointer as usize);
        let result = DnsName::decode_name(r);
        r.seek(current_pos);

        result
    }

    fn encode(self) -> Vec<u8> {
        let mut encoded = vec![];
        for label in self.0.split(".") {
            assert!(
                0 < label.len() && label.len() <= 64,
                "dns label not in len range"
            );
            // encoded.push(0);
            encoded.push(label.len() as u8);
            encoded.extend_from_slice(label.as_bytes());
        }
        encoded.push(0);

        encoded
    }
}

#[derive(Debug)]
struct DnsQuestion {
    name: DnsName,
    qtype: u16,
    qclass: u16,
}

impl DnsQuestion {
    fn new_for_name(name: &str) -> Self {
        let name = DnsName::new(name);

        Self {
            name,
            qtype: 1,  // TYPE_A IPv4
            qclass: 1, // CLASS_IN Internet
        }
    }

    fn decode(r: &mut Reader) -> Self {
        let name = DnsName::decode(r);
        let b = r.read(4);

        Self {
            name,
            qtype: u16::from_be_bytes(b[0..2].try_into().unwrap()),
            qclass: u16::from_be_bytes(b[2..4].try_into().unwrap()),
        }
    }

    fn encode(self) -> Vec<u8> {
        let mut buffer = vec![];

        buffer.extend(self.name.encode());
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

#[derive(Debug)]
struct DnsRecord {
    name: DnsName,
    rtype: u16,
    rclass: u16,
    ttl: u16,
    data: Vec<u8>,
}

impl DnsRecord {
    fn decode(r: &mut Reader) -> Self {
        let name = DnsName::decode(r);
        let b = r.read(10);

        let rtype = u16::from_be_bytes(b[0..2].try_into().unwrap());
        let rclass = u16::from_be_bytes(b[2..4].try_into().unwrap());
        let ttl = u16::from_be_bytes(b[4..6].try_into().unwrap());
        let data_len = u32::from_be_bytes(b[6..10].try_into().unwrap());

        let data = r.read(data_len as usize).to_vec();

        Self {
            name,
            rtype,
            rclass,
            ttl,
            data,
        }
    }
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
    let socket = UdpSocket::bind("0.0.0.0:0").expect("could not bind socket");
    socket
        .connect("8.8.8.8:53")
        .expect("could not connect to DNS");

    socket
        .send(&dns_query)
        .expect("error on sending query to DNS");

    let mut recv_buffer = [0 as u8; 512];
    let recv_size = socket
        .recv(&mut recv_buffer)
        .expect("error on response receiving.");

    let mut reader = Reader::new(&recv_buffer, recv_size);
    let header = DnsHeader::decode(&mut reader);
    dbg!(&header);
    let question = DnsQuestion::decode(&mut reader);
    dbg!(&question);
    let record = DnsRecord::decode(&mut reader);
    dbg!(&record);
}
