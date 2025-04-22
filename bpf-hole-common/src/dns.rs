#[repr(C)]
pub struct DNSPacket {
    pub ID: u16, //2 byte
    pub HEADER_DATA: u16,
  //pub QR: bool,
  //pub OpCode: //4 bit int
  //pub AA: bool,
  //pub TC: bool,
  //pub RD: bool,
  //pub RA: bool,
  //pub Z: // 3 static zero bits
  //pub RCODE: //4 bit int
    pub QDCOUNT: u16, //2 byte
    pub ANCOUNT: u16, //2 byte
    pub NSCOUNT: u16, //2 byte
    pub ARCOUNT: u16, //2 byte
    //pub Payload: &'static[u8],
}
 impl DNSPacket{
    pub const HDRLEN:usize = 12;
 }
