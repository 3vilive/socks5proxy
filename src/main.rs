use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
};

use log::{error, info};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();

    let addr = "127.0.0.1:18080";
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("server listen at {addr}");

    loop {
        let (stream, _) = listener.accept().await?;
        if let Err(err) = process(stream).await {
            error!("failed to process stream: {err}");
        }
    }
}

async fn process(mut stream: TcpStream) -> io::Result<()> {
    info!("process connection from {}", stream.peer_addr()?);

    // handshake
    process_socks5_method_negotiation(&mut stream).await?;

    // connect
    let dest_stream = process_socks5_request(&mut stream).await?;

    // relay
    let mut dest_stream = match dest_stream {
        Some(dest_stream) => dest_stream,
        None => return Ok(()),
    };
    tokio::io::copy_bidirectional(&mut stream, &mut dest_stream).await?;

    Ok(())
}

// X'00' NO AUTHENTICATION REQUIRED
// X'01' GSSAPI
// X'02' USERNAME/PASSWORD
// X'03' to X'7F' IANA ASSIGNED
// X'80' to X'FE' RESERVED FOR PRIVATE METHODS
// X'FF' NO ACCEPTABLE METHODS

async fn process_socks5_method_negotiation(stream: &mut TcpStream) -> io::Result<()> {
    // +----+----------+----------+
    // |VER | NMETHODS | METHODS  |
    // +----+----------+----------+
    // | 1  |    1     | 1 to 255 |
    // +----+----------+----------+
    let ver = stream.read_u8().await?;
    let nmethods = stream.read_u8().await?;
    let mut methods: Vec<u8> = Vec::with_capacity(nmethods as usize);
    for _ in 0..nmethods {
        methods.push(stream.read_u8().await?);
    }

    // +----+--------+
    // |VER | METHOD |
    // +----+--------+
    // | 1  |   1    |
    // +----+--------+
    stream.write_u8(ver).await?;
    stream.write_u8(0x00).await?;
    stream.flush().await?;

    Ok(())
}

const ATYP_IP_V4: u8 = 0x01;
const ATYP_DOMAIN_NAME: u8 = 0x03;
const ATYP_IP_V6: u8 = 0x04;

async fn process_socks5_request(stream: &mut TcpStream) -> io::Result<Option<TcpStream>> {
    // request
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    let ver = stream.read_u8().await?;
    let cmd = stream.read_u8().await?;
    let rsv = stream.read_u8().await?;
    let atyp = stream.read_u8().await?;

    info!(
        "process request from {}: ver={:02X}, cmd={:02X}, atyp={:02X}",
        stream.peer_addr()?,
        ver,
        cmd,
        atyp,
    );

    let socket_addr = match atyp {
        ATYP_IP_V4 => {
            let mut ipv4: [u8; 4] = [0; 4];
            stream.read_exact(&mut ipv4).await?;
            let port = stream.read_u16().await?;

            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(ipv4[0], ipv4[1], ipv4[2], ipv4[3])),
                port,
            )
        }
        ATYP_IP_V6 => {
            let mut ipv6: [u8; 16] = [0; 16];
            stream.read_exact(&mut ipv6).await?;
            let port = stream.read_u16().await?;

            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(
                    u16::from_be_bytes([ipv6[0], ipv6[1]]),
                    u16::from_be_bytes([ipv6[2], ipv6[3]]),
                    u16::from_be_bytes([ipv6[4], ipv6[5]]),
                    u16::from_be_bytes([ipv6[6], ipv6[7]]),
                    u16::from_be_bytes([ipv6[8], ipv6[9]]),
                    u16::from_be_bytes([ipv6[10], ipv6[11]]),
                    u16::from_be_bytes([ipv6[12], ipv6[13]]),
                    u16::from_be_bytes([ipv6[14], ipv6[14]]),
                )),
                port,
            )
        }
        ATYP_DOMAIN_NAME => {
            let domain_len = stream.read_u8().await? as usize;
            let mut domain_buffer = vec![0u8; domain_len];
            stream.read_exact(&mut domain_buffer).await?;

            let domain_str = std::str::from_utf8(&domain_buffer)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            let port = stream.read_u16().await?;

            let addr_str = format!("{}:{}", domain_str, port);
            let mut socket_addrs = addr_str
                .to_socket_addrs()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            socket_addrs.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, "No valid socket address found")
            })?
        }
        _ => return Err(io::Error::new(io::ErrorKind::Other, "Invlaid ATYP")),
    };

    info!(
        "process request from {}: socket_addr: {}",
        stream.peer_addr()?,
        socket_addr,
    );

    // replies
    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+

    let dest_stream = match TcpStream::connect(socket_addr).await {
        Ok(dest_stream) => Some(dest_stream),
        Err(e) => {
            use io::ErrorKind;

            let rep: u8;
            match e.kind() {
                ErrorKind::ConnectionRefused => rep = 0x05,
                ErrorKind::AddrNotAvailable => rep = 0x04,
                _ => rep = 0x03,
            };

            stream
                .write_all(&[0x05, rep, rsv, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .await?;

            None
        }
    };

    stream
        .write_all(&[
            0x05, // VER
            0x00, // REP
            rsv,  // RSV
            0x01, // ATYP
            0x00, 0x00, 0x00, 0x00, // BND.ADDR
            0x00, 0x00, // BND.PORT
        ])
        .await?;

    Ok(dest_stream)
}
