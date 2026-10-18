use color_eyre::eyre::ensure;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{mem::MaybeUninit, time::Duration};

use tcping::{ICMPPacket, ICMPType};

fn icmp_echo_request(
    socket: &Socket,
    icmp_packet: &[u8],
    dst: &SockAddr,
    timeout: Duration,
) -> color_eyre::Result<Vec<u8>> {
    socket.set_read_timeout(Some(timeout))?;
    socket.send_to(icmp_packet, dst)?;

    let mut rx_buf = [MaybeUninit::<u8>::uninit(); 1024]; // NOTE: hardcoding receive buffer size for now
    let (bytes_read, addr) = socket.recv_from(&mut rx_buf)?;

    // TODO: Add more validation for the received packet to ensure it matches the echo request we sent
    ensure!(
        addr.as_socket() == dst.as_socket(),
        "received packet source address doesn't match destination address"
    );

    let ip_packet = rx_buf[..bytes_read]
        .iter()
        .map(|byte| unsafe { byte.assume_init() })
        .collect::<Vec<_>>();
    let ihl = ((ip_packet[0] & 0x0f) * 4) as usize;

    // Raw ipv4 sockets include ipv4 header, so we strip ipv4 header and return icmp message
    let icmp_echo_reply = ip_packet[ihl..].to_vec();

    Ok(icmp_echo_reply)
}

fn main() -> color_eyre::Result<()> {
    let icmp_packet = ICMPPacket::new(ICMPType::Echo, 0x00, 0x01, vec![1, 3, 4, 5]);

    let socket = Socket::new_raw(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    let dst: SockAddr = "1.1.1.1:0".parse::<std::net::SocketAddr>()?.into();
    dbg!(ICMPPacket::try_from(
        icmp_echo_request(
            &socket,
            &icmp_packet.as_bytes(),
            &dst,
            Duration::from_secs(3),
        )?
        .as_slice(),
    )?);

    Ok(())
}
