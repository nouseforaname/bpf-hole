#[repr(C)]
pub struct DNSPacket {
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
    //pub Payload: &'static[u8],

}
 impl DNSPacket{
    pub const HDRLEN:usize = 12;
    pub const DATA_SUFFIX_BYTES:usize = 4;
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
            buf[i] = buf[i+1];
            bytes_until_segment_ends -= 1;
            continue;
        }

        // the TLD . (after the TLD) marks the end of the hostname. QNAME uses an empty octet -> 0b00
        bytes_until_segment_ends = buf[i+1];
        if bytes_until_segment_ends == 0{
            zero_rest = true;
            buf[i]=0;
        }else{
            buf[i] = 46;
        }
    }
}
pub fn extract_host_from_qname(buf: &mut [u8]) -> &str {
    ""
}
