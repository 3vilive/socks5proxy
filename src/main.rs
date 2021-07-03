use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use std::{u16, str};


#[tokio::main]
async fn main() -> io::Result<()> {
    let addr = "0.0.0.0:11080";
    let listener = TcpListener::bind(addr).await?;
    println!("listening at {}", addr);

    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                tokio::spawn(async move {
                    if let Err(err) = process_socks5_proxy(socket).await {
                        println!("process socket({:?}) error: {:?}", addr, err);
                    }
                });
            },
            Err(err) => {
                println!("accept error {:?}", err)
            }
        }
    }
}

async fn process_socks5_proxy(socket: TcpStream) -> io::Result<()> {
    let (mut rd, mut wr) = io::split(socket);

    // socks5 auth
    // ver nmethods methods
    let mut ver_buf = [0; 2];
    rd.read_exact(&mut ver_buf).await?;
    let _ver = ver_buf[0];
    let nmethods = ver_buf[1];

    // methods
    let mut methods_buf = vec![0; nmethods as usize];
    rd.read(&mut methods_buf).await?; 

    // ver method
    wr.write_all(&[0x05, 0x00]).await?;

    // socks5 connect
    // ver cmd rsv atyp dst.addr dst.port
    let mut connect_buf = [0; 4];
    rd.read_exact(&mut connect_buf).await?;


    // parse dst addr
    // 0x1 IPv4 4 bytes
    // 0x3 hostname first byte as length
    // 0x4 IPv6 16 bytes
    let atyp = connect_buf[3];
    let dst_addr: String;
    match atyp {
        0x1 => {
            // IPv4 4 bytes
            let mut ipv4_buf = [0; 4];
            rd.read_exact(&mut ipv4_buf).await?;
            dst_addr = format!("{}.{}.{}.{}", ipv4_buf[0], ipv4_buf[1], ipv4_buf[2], ipv4_buf[3])
        },
        0x3 => {
            // hostname
            let mut nhostname_buf = [0; 1];
            rd.read_exact(&mut nhostname_buf).await?;

            let mut hostname_buf = vec![0; nhostname_buf[0] as usize];
            rd.read_exact(&mut hostname_buf).await?;

            dst_addr = match str::from_utf8(&hostname_buf) {
                Ok(hostname) => {
                    hostname.to_string()
                },
                Err(err) => {
                    let wrap_err = io::Error::new(io::ErrorKind::Other, format!("parse buffer error: {:?}", err));
                    return Err(wrap_err)
                },
            };
        },
        _ => {
            let err = io::Error::new(io::ErrorKind::Other, format!("unsupported atype {}", atyp));
            return Err(err)
        }
    }

    let mut dst_port_buf = [0; 2];
    rd.read_exact(&mut dst_port_buf).await?;
    let dst_port = u16::from_be_bytes(dst_port_buf);
    let dst_addr = format!("{}:{}", dst_addr, dst_port);

    println!("dst_addr: {}", dst_addr);

    let dst_socket = TcpStream::connect(dst_addr).await?;
    let (mut dst_rd, mut dst_wr) = io::split(dst_socket);

    // tell client we are ready
    // ver rep rsv atyp bnd.addr bnd.prot
    wr.write(&[0x5, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x50]).await?;


    // forward
    let t1 = tokio::spawn(async move {
        if let Err(err) = io::copy(&mut rd, &mut dst_wr).await {
            println!("copy reader to dst writer error: {:?}", err);
        }
    });

    let t2 = tokio::spawn(async move {
        if let Err(err) = io::copy(&mut dst_rd, &mut wr).await {
            println!("copy dst reader to writer error: {:?}", err);
        }
    });

    let _ = tokio::join!(
        t1,
        t2,
    );

    Ok(())
}