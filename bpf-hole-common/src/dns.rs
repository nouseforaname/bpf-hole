#[repr(C)]
pub struct DNSHeader {
    pub ID: u16, //2 byte
    pub HEADER_DATA: u16,
    // QR: bit,
    // OpCode: //4 bit int
    // AA: bit,
    // TC: bit,
    // RD: bit,
    // RA: bit,
    // Z: // 3 static zero bits
    // RCODE: //4 bit int
    pub QDCOUNT: u16, //2 byte
    pub ANCOUNT: u16, //2 byte
    pub NSCOUNT: u16, //2 byte
    pub ARCOUNT: u16, //2 byte
}

impl DNSHeader {
    pub const HDRLEN: usize = 12;
    pub const QNAME_SUFFIX: usize = 4;
}
// using u8 arrays since the data isn't aligned. So deserializing from network bytes can be done by pointer casting instead of writing custom logig
// TODO figure out if there's a way to have a badly aligned struct deal with the missing padding via `repr(packed)`
#[repr(C)]
pub struct DNSAnswer {
    pub rtype: [u8; 2],
    pub class: [u8; 2],
    pub ttl: [u8; 4],
    pub data_len: [u8; 2],
}
impl DNSAnswer {
    pub fn rtype(&self) -> u16 {
        u16::from_be_bytes(self.rtype)
    }
    pub fn ttl(&self) -> u32 {
        u32::from_be_bytes(self.ttl)
    }
    pub fn class(&self) -> u16 {
        u16::from_be_bytes(self.class)
    }
    pub fn data_len(&self) -> u16 {
        u16::from_be_bytes(self.data_len)
    }
}
pub fn decode_qname_data(buf: &mut [u8]) {
    let mut bytes_until_segment_ends = buf[0];
    let mut zero_rest = false;
    for i in 0..buf.len() - 1 {
        if zero_rest {
            buf[i] = 0;
            continue;
        }
        if bytes_until_segment_ends > 0 {
            buf[i] = buf[i + 1];
            bytes_until_segment_ends -= 1;
            continue;
        }

        // the TLD . (after the TLD) marks the end of the hostname. QNAME uses an empty octet -> 0b00
        bytes_until_segment_ends = buf[i + 1];
        if bytes_until_segment_ends == 0 {
            zero_rest = true;
            buf[i] = 0;
        } else {
            buf[i] = 46;
        }
    }
}
