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
