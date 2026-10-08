type ICMPChecksum = u16;

fn calculate_icmp_checksum(icmp_packet: &[u8]) -> ICMPChecksum {
    let mut sum: u32 = 0;
    let mut chunked_icmp_packet = icmp_packet.chunks_exact(2);
    for chunk in &mut chunked_icmp_packet {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&remainder) = chunked_icmp_packet.remainder().first() {
        sum += u16::from_be_bytes([remainder, 0x00]) as u32;
    }

    while sum >> 16 != 0 {
        let lower_bits = sum & u16::MAX as u32;
        let carry = sum >> 16;
        sum = carry + lower_bits;
    }

    !(sum as u16)
}

fn main() -> color_eyre::Result<()> {
    let sample_icmp_packet = [0x08, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x20];
    dbg!(calculate_icmp_checksum(&sample_icmp_packet));

    Ok(())
}
