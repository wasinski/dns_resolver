use rand::Rng;

use crate::Result;

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;

#[derive(Debug)]
pub struct IPv4([u8; 4]);

impl std::str::FromStr for IPv4 {
    type Err = &'static str;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();

        if parts.len() != 4 {
            return Err("incorrect length of IPv4 address");
        }

        let mut octets = [0u8; 4];
        for (i, part) in parts.iter().enumerate() {
            octets[i] = part.parse::<u8>().map_err(|_| "Invalid octet")?;
        }

        Ok(Self(octets))
    }
}

impl std::fmt::Display for IPv4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

impl From<IPv4> for String {
    fn from(val: IPv4) -> Self {
        format!("{}.{}.{}.{}", val.0[0], val.0[1], val.0[2], val.0[3])
    }
}

impl TryFrom<&str> for IPv4 {
    type Error = &'static str;
    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<Vec<u8>> for IPv4 {
    type Error = &'static str;
    fn try_from(value: Vec<u8>) -> std::result::Result<Self, Self::Error> {
        if value.len() != 4 {
            return Err("incorrect length of IPv4 address");
        }

        Ok(IPv4(value[0..4].try_into().unwrap()))
    }
}

#[derive(Debug)]
pub struct DnsHeader {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

impl DnsHeader {
    pub fn new_with_rand_id(flags: u16) -> Self {
        let mut rng = rand::thread_rng();

        let id: u16 = rng.gen();
        let num_questions = 1;

        Self {
            id,
            flags,
            num_questions,
            num_answers: 0,
            num_authorities: 0,
            num_additionals: 0,
        }
    }

    pub fn decode(r: &mut Reader) -> Self {
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

    pub fn encode(self) -> Vec<u8> {
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

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    len: usize,
}

impl Reader<'_> {
    pub fn new(buf: &[u8], len: usize) -> Reader<'_> {
        Reader { buf, pos: 0, len }
    }

    fn read(&mut self, len: usize) -> &[u8] {
        assert!(
            self.pos < self.len && self.pos + len <= self.len,
            "limit len: {}, pos: {}, new pos: {}",
            self.len,
            self.pos,
            self.pos + len
        );
        let r = &self.buf[self.pos..self.pos + len];
        self.pos += len;

        r
    }

    fn seek(&mut self, pos: usize) {
        assert!(pos <= self.len, "!{} <= {}", pos, self.len);
        self.pos = pos;
    }

    fn tell(&self) -> usize {
        self.pos
    }
}

#[derive(Debug)]
pub struct DnsName(String);

impl DnsName {
    fn new(s: String) -> Self {
        assert!(
            s.is_ascii(),
            "dns name must not contain non-ascii characters"
        );
        Self(s)
    }

    fn decode(r: &mut Reader) -> Self {
        Self::new(Self::decode_name(r))
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
        for label in self.0.split('.') {
            assert!(
                !label.is_empty() && label.len() <= 64,
                "dns label must be 1 up to 64 chacters"
            );
            encoded.push(label.len() as u8);
            encoded.extend_from_slice(label.as_bytes());
        }
        encoded.push(0);

        encoded
    }
}

#[derive(Debug)]
pub struct DnsQuestion {
    name: DnsName,
    qtype: u16,
    qclass: u16,
}

impl DnsQuestion {
    pub fn new_for_name(name: String, record_type: u16) -> Self {
        let name = DnsName::new(name);

        Self {
            name,
            qtype: record_type,
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

    pub fn encode(self) -> Vec<u8> {
        let mut buffer = vec![];

        buffer.extend(self.name.encode());
        buffer.extend(self.qtype.to_be_bytes());
        buffer.extend(self.qclass.to_be_bytes());

        buffer
    }
}

#[derive(Debug)]
pub struct DnsRecord {
    name: DnsName,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    data: Vec<u8>,
    parsed_data: ParsedData,
}

impl DnsRecord {
    fn decode(r: &mut Reader) -> Self {
        let name = DnsName::decode(r);
        let b = r.read(10);

        let rtype = u16::from_be_bytes(b[0..2].try_into().unwrap());
        let rclass = u16::from_be_bytes(b[2..4].try_into().unwrap());
        let ttl = u32::from_be_bytes(b[4..8].try_into().unwrap());
        let data_len = u16::from_be_bytes(b[8..10].try_into().unwrap());
        // let data = r.copy(data_len as usize).to_vec();
        let data = [0_u8; 0];

        let parsed_data = match rtype {
            TYPE_A => ParsedData::parse_ip_address(r.read(data_len as usize)),
            TYPE_NS => ParsedData::parse_domain_name(r),
            _ => ParsedData::other(r.read(data_len as usize)), // have an enum here
        };

        Self {
            name,
            rtype,
            rclass,
            ttl,
            data: data.into(),
            parsed_data,
        }
    }
}

#[derive(Debug)]
enum ParsedData {
    DomainName(DnsName),
    IpAddr(IPv4),
    Other,
}

impl ParsedData {
    fn parse_ip_address(data: &[u8]) -> Self {
        let a = IPv4(data.try_into().unwrap());

        Self::IpAddr(a)
    }

    fn parse_domain_name(r: &mut Reader) -> Self {
        let n = DnsName::decode(r);

        Self::DomainName(n)
    }

    fn other(_data: &[u8]) -> Self {
        Self::Other
    }
}

#[derive(Debug)]
pub struct DnsPacket {
    header: DnsHeader,
    questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn decode(r: &mut Reader) -> Self {
        let header = DnsHeader::decode(r);
        let questions = (0..header.num_questions)
            .map(|_| DnsQuestion::decode(r))
            .collect();
        let answers = (0..header.num_answers)
            .map(|_| DnsRecord::decode(r))
            .collect();
        let authorities = (0..header.num_authorities)
            .map(|_| DnsRecord::decode(r))
            .collect();
        let additionals = (0..header.num_additionals)
            .map(|_| DnsRecord::decode(r))
            .collect();

        Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        }
    }

    pub fn parse_ip_address(&self) -> Result<String> {
        if let Some(record) = self
            .answers
            .iter()
            .find(|r| matches!(r.parsed_data, ParsedData::IpAddr(_)))
        {
            if let ParsedData::IpAddr(addr) = &record.parsed_data {
                Ok(addr.to_string())
            } else {
                Err("type A record not found".into())
            }
        } else {
            Err("type A record not found".into())
        }
    }

    pub fn parse_next_name_server_ip(&self) -> Result<String> {
        if let Some(record) = self
            .additionals
            .iter()
            .find(|r| matches!(r.parsed_data, ParsedData::IpAddr(_)))
        {
            if let ParsedData::IpAddr(addr) = &record.parsed_data {
                Ok(addr.to_string())
            } else {
                Err("type A record not found".into())
            }
        } else {
            Err("type A record not found".into())
        }
    }

    pub fn parse_next_name_server_domain(&self) -> Result<String> {
        if let Some(record) = self
            .authorities
            .iter()
            .find(|r| matches!(r.parsed_data, ParsedData::DomainName(_)))
        {
            if let ParsedData::DomainName(name) = &record.parsed_data {
                Ok(name.0.clone())
            } else {
                Err("type NS record not found".into())
            }
        } else {
            Err("type NS record not found".into())
        }
    }
}
