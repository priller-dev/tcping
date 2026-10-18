use super::checksum::calculate_icmp_checksum;
use color_eyre::eyre::{bail, ensure};

pub type ICMPChecksum = u16;
pub type ICMPPayload = Vec<u8>;

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum ICMPType {
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
pub struct ICMPPacket {
    pub type_: ICMPType,
    code: u8,
    pub checksum: ICMPChecksum,
    pub identifier: u16,
    pub sequence_number: u16,
    pub payload: ICMPPayload,
}

impl ICMPPacket {
    pub fn new(
        type_: ICMPType,
        identifier: u16,
        sequence_number: u16,
        payload: ICMPPayload,
    ) -> Self {
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

    pub fn as_bytes(&self) -> Vec<u8> {
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
