use std::{fs::File, io::BufReader};

use aya::maps::{HashMap, MapData};
use bpf_hole_common::consts::PACKET_DATA_BUF_LEN;
use log::info;

pub fn read_blocklist_to_map(
    map: &mut HashMap<&mut MapData, [u8; PACKET_DATA_BUF_LEN], u8>,
    file: &str,
) -> anyhow::Result<()> {
    let file = File::open(file)?;
    let reader = BufReader::new(file);
    for (i, line) in std::io::BufRead::lines(reader).enumerate() {
        match line {
            Ok(v) => {
                println!("adding '{}' to blocklist", v);
                let mut bytes = [0u8; PACKET_DATA_BUF_LEN];
                for (bi, b) in v.bytes().enumerate() {
                    bytes[bi] = b as u8;
                }
                map.insert(bytes, 1u8, 0)?;
            }
            Err(e) => println!("failed reading line {} with {}", i, e),
        }
    }
    Ok(())
}
