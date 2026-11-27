//! A local, credential-free HTTP CONNECT transport. The caller performs TLS
//! using the official origin's hostname after this socket becomes a tunnel.
use std::{io, net::SocketAddr};

use http::Uri;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::Result;

#[derive(Clone, Copy)]
pub(super) struct HttpConnect(SocketAddr);

impl HttpConnect {
    pub(super) fn parse(value: &str) -> Result<Self> {
        const BAD: &str = "http_proxy must be an HTTP URL with a literal loopback IP and explicit port (no authentication, path or query)";
        if value.len() > 128 || value.contains(['#', '?', '@']) {
            return Err(BAD.into());
        }
        let uri: Uri = value.parse().map_err(|_| BAD)?;
        if uri.scheme_str() != Some("http") || uri.path() != "/" {
            return Err(BAD.into());
        }
        let endpoint: SocketAddr = uri
            .authority()
            .ok_or(BAD)?
            .as_str()
            .parse()
            .map_err(|_| BAD)?;
        if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
            return Err(BAD.into());
        }
        Ok(Self(endpoint))
    }

    pub(super) async fn tunnel(self, destination: SocketAddr) -> io::Result<TcpStream> {
        let mut tcp = TcpStream::connect(self.0).await?;
        tcp.set_nodelay(true)?;
        // SocketAddr formats IPv6 as [address]:port. The numeric authority
        // makes the chosen destination independent of the proxy's DNS.
        let request = format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n");
        tcp.write_all(request.as_bytes()).await?;

        const MAX_HEAD: usize = 8 * 1024;
        let mut head = Vec::with_capacity(256);
        let mut chunk = [0; 512];
        loop {
            let n = tcp.read(&mut chunk).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "HTTP proxy closed before responding",
                ));
            }
            let start = head.len().saturating_sub(3);
            if n > MAX_HEAD - head.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP proxy response headers too large",
                ));
            }
            head.extend_from_slice(&chunk[..n]);
            let Some(end) = head[start..].windows(4).position(|b| b == b"\r\n\r\n") else {
                continue;
            };
            if start + end + 4 != head.len() {
                // A TLS origin cannot send anything before our ClientHello.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP proxy sent unexpected bytes after response",
                ));
            }
            break;
        }
        let first = head.split(|&b| b == b'\r').next().unwrap_or_default();
        let mut parts = first.split(|&b| b == b' ');
        if !matches!(parts.next(), Some(b"HTTP/1.1" | b"HTTP/1.0")) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP proxy returned an invalid status line",
            ));
        }
        match parts.next() {
            Some([b'2', a, b]) if a.is_ascii_digit() && b.is_ascii_digit() => Ok(tcp),
            _ => Err(io::Error::other("HTTP proxy refused CONNECT")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn only_literal_loopback_http_proxies_with_ports() {
        assert!(HttpConnect::parse("http://127.0.0.1:2080").is_ok());
        assert!(HttpConnect::parse("http://[::1]:2080/").is_ok());
        for value in [
            "https://127.0.0.1:2080",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:2080/info",
            "http://localhost:2080",
            "http://192.0.2.1:2080",
            "http://user@127.0.0.1:2080",
            "http://127.0.0.1:2080/?secret=true",
        ] {
            assert!(HttpConnect::parse(value).is_err(), "accepted {value}");
        }
    }

    #[tokio::test]
    async fn ipv6_authority_is_literal_and_a_refusal_is_not_a_tunnel() {
        for reply in [
            &b"HTTP/1.1 200 Connection established\r\n\r\n"[..],
            &b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"[..],
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy = HttpConnect(listener.local_addr().unwrap());
            let peer = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                let expected = b"CONNECT [2404:6800:4007:800::200a]:443 HTTP/1.1\r\nHost: [2404:6800:4007:800::200a]:443\r\n\r\n";
                let mut bytes = vec![0; expected.len()];
                s.read_exact(&mut bytes).await.unwrap();
                assert_eq!(bytes, expected);
                s.write_all(reply).await.unwrap();
            });
            assert_eq!(
                proxy
                    .tunnel("[2404:6800:4007:800::200a]:443".parse().unwrap())
                    .await
                    .is_ok(),
                reply.starts_with(b"HTTP/1.1 200")
            );
            peer.await.unwrap();
        }
    }
}
