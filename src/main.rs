use color_eyre::eyre::{bail, ensure};

type ICMPChecksum = u16;
type ICMPPayload = Vec<u8>;

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum ICMPType {
    Echo = 0x08,
    EchoReply = 0x00,
}

impl TryFrom<u8> for ICMPType {
    type Error = color_eyre::eyre::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x08 => Self::Echo,
            0x00 => Self::EchoReply,
            _ => bail!("Not supported ICMP type: {value}"),
        })
    }
}

#[derive(Debug)]
struct ICMPPacket {
    type_: ICMPType,
    code: u8,
    checksum: ICMPChecksum,
    identifier: u16,
    sequence_number: u16,
    payload: ICMPPayload,
}

impl ICMPPacket {
    fn new(type_: ICMPType, identifier: u16, sequence_number: u16, payload: ICMPPayload) -> Self {
        let mut icmp_packet = Self {
            type_,
            code: 0, // for icmp echo and echo reply requests the code is always 0
            checksum: 0x00,
            identifier,
            sequence_number,
            payload,
        };

        icmp_packet.checksum = calculate_icmp_checksum(&icmp_packet.as_bytes());

        icmp_packet
    }

    fn as_bytes(&self) -> Vec<u8> {
        let header = &[
            [self.type_ as u8, self.code],
            self.checksum.to_be_bytes(),
            self.identifier.to_be_bytes(),
            self.sequence_number.to_be_bytes(),
        ]
        .concat();
        let payload = self.payload.as_slice();
        let mut bytes = Vec::<u8>::with_capacity(header.len() + payload.len());
        bytes.extend_from_slice(header);
        bytes.extend_from_slice(payload);
        bytes
    }
}

impl TryFrom<&[u8]> for ICMPPacket {
    type Error = color_eyre::eyre::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        ensure!(
            bytes.len() >= 8,
            "ICMP packet size should be at least 8 bytes, but got {} bytes",
            bytes.len()
        );
        Ok(Self {
            type_: ICMPType::try_from(bytes[0])?,
            code: bytes[1],
            checksum: u16::from_be_bytes(bytes[2..4].try_into()?),
            identifier: u16::from_be_bytes(bytes[4..6].try_into()?),
            sequence_number: u16::from_be_bytes(bytes[6..8].try_into()?),
            payload: bytes[8..].to_vec(),
        })
    }
}

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
    let icmp_packet = ICMPPacket::new(ICMPType::Echo, 0x00, 0x01, vec![1, 3, 4, 5]);
    dbg!(icmp_packet);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_checksum_empty() {
        assert_eq!(calculate_icmp_checksum(&[]), 0xffff);
    }

    #[test]
    fn test_icmp_checksum_single_zero() {
        assert_eq!(calculate_icmp_checksum(&[0x00]), 0xffff);
    }

    #[test]
    fn test_icmp_checksum_single_byte() {
        assert_eq!(calculate_icmp_checksum(&[0x01]), 0xfeff);
    }

    #[test]
    fn test_icmp_checksum_two_bytes() {
        assert_eq!(calculate_icmp_checksum(&[0x01, 0x02]), 0xfefd);
    }

    #[test]
    fn test_icmp_checksum_maximum_16_bit_word() {
        assert_eq!(calculate_icmp_checksum(&[0xff, 0xff]), 0x0000);
    }

    #[test]
    fn test_icmp_checksum_four_bytes() {
        assert_eq!(calculate_icmp_checksum(&[0x01, 0x02, 0x03, 0x04]), 0xfbf9);
    }

    #[test]
    fn test_icmp_checksum_echo_header() {
        assert_eq!(calculate_icmp_checksum(&[0x08, 0x00, 0x00, 0x00]), 0xf7ff);
    }

    #[test]
    fn test_icmp_checksum_echo_request() {
        assert_eq!(
            calculate_icmp_checksum(&[0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01,]),
            0xe5ca
        );
    }

    #[test]
    fn test_icmp_checksum_mixed_even_length() {
        assert_eq!(
            calculate_icmp_checksum(&[
                0x45, 0x00, 0x00, 0x54, 0x12, 0x34, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00,
            ]),
            0x2876
        );
    }

    #[test]
    fn test_icmp_checksum_mixed_odd_length() {
        assert_eq!(
            calculate_icmp_checksum(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03,]),
            0x5e60
        );
    }
}
