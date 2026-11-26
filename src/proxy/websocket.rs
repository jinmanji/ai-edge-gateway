use std::{sync::Arc, time::Duration};

use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use base64::{Engine, engine::general_purpose::STANDARD};
use http::{HeaderValue, Method, Request, Response, StatusCode, Version, header, request::Parts};
use hyper::{
    body::{Body, Incoming},
    upgrade::{OnUpgrade, Upgraded},
};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{copy, split},
    time::timeout,
};

use super::{
    body::{self, Fault, ProxyBody},
    headers,
};
use crate::server::ConnectionLease;

pub struct Validated(HeaderValue);
pub struct Upgrade {
    expected: HeaderValue,
    client: OnUpgrade,
}
pub struct Tunnel {
    client: OnUpgrade,
    server: OnUpgrade,
    _connection: Option<Arc<ConnectionLease>>,
}

pub fn validate(r: &Request<ProxyBody>) -> Result<Validated, Box<Response<ProxyBody>>> {
    let bad = || {
        Box::new(body::text(
            StatusCode::BAD_REQUEST,
            "invalid HTTP/1.1 WebSocket upgrade\n",
        ))
    };
    if r.method() != Method::GET
        || r.version() != Version::HTTP_11
        || !r.body().is_end_stream()
        || !headers::has_token(r.headers(), header::CONNECTION, "upgrade")
        || r.headers().contains_key(header::TRANSFER_ENCODING)
        || headers::content_length(r.headers())
            .map_err(|_| bad())?
            .is_some_and(|n| n != 0)
    {
        return Err(bad());
    }
    let k = headers::single(r.headers(), header::SEC_WEBSOCKET_KEY)
        .ok()
        .flatten()
        .ok_or_else(bad)?;
    let v = headers::single(r.headers(), header::SEC_WEBSOCKET_VERSION)
        .ok()
        .flatten()
        .ok_or_else(bad)?;
    let u = headers::single(r.headers(), header::UPGRADE)
        .ok()
        .flatten()
        .ok_or_else(bad)?;
    if v.as_bytes() != b"13"
        || !u.as_bytes().eq_ignore_ascii_case(b"websocket")
        || k.as_bytes().len() != 24
        || !STANDARD
            .decode(k.as_bytes())
            .is_ok_and(|bytes| bytes.len() == 16)
    {
        return Err(bad());
    }
    const GUID: &[u8; 36] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut hash = [0u8; 60];
    hash[..24].copy_from_slice(k.as_bytes());
    hash[24..].copy_from_slice(GUID);
    let expected = STANDARD.encode(digest(&SHA1_FOR_LEGACY_USE_ONLY, &hash));
    Ok(Validated(
        HeaderValue::from_str(&expected).map_err(|_| bad())?,
    ))
}

pub fn take(v: Validated, parts: &mut Parts) -> Upgrade {
    let client = parts
        .extensions
        .remove::<OnUpgrade>()
        .unwrap_or_else(|| hyper::upgrade::on(Request::new(())));
    Upgrade {
        expected: v.0,
        client,
    }
}

impl Upgrade {
    pub fn set_headers(&self, request: &mut Request<ProxyBody>) {
        request.headers_mut().remove(header::CONTENT_LENGTH);
        request
            .headers_mut()
            .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        request
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    }

    pub fn tunnel(
        self,
        mut response: Response<Incoming>,
        conn: Option<Arc<ConnectionLease>>,
        limit: usize,
    ) -> Result<(Response<ProxyBody>, Tunnel), Fault> {
        if headers::header_size(response.headers()) > limit
            || response.version() != Version::HTTP_11
            || !headers::has_token(response.headers(), header::CONNECTION, "upgrade")
            || !headers::single(response.headers(), header::UPGRADE)
                .map_err(|_| Fault::Framing)?
                .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
            || headers::single(response.headers(), header::SEC_WEBSOCKET_ACCEPT)
                .map_err(|_| Fault::Framing)?
                != Some(&self.expected)
        {
            return Err(Fault::Framing);
        }
        headers::remove_hop(response.headers_mut()).map_err(|_| Fault::Framing)?;
        response.headers_mut().remove(header::CONTENT_LENGTH);
        response
            .headers_mut()
            .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        let server = hyper::upgrade::on(&mut response);
        let tunnel = Tunnel {
            client: self.client,
            server,
            _connection: conn,
        };
        Ok((response.map(|_| body::empty()), tunnel))
    }
}
impl Tunnel {
    pub async fn run(self) {
        let Ok(Ok((a, b))) = timeout(Duration::from_secs(10), async {
            tokio::try_join!(self.client, self.server)
        })
        .await
        else {
            return;
        };
        // First EOF/error drops both sides; a half-closed downstream must not
        // leave a billable realtime upstream session around.
        let (mut ar, mut aw) = split(TokioIo::<Upgraded>::new(a));
        let (mut br, mut bw) = split(TokioIo::<Upgraded>::new(b));
        tokio::select! { _ = copy(&mut ar, &mut bw) => {}, _ = copy(&mut br, &mut aw) => {} }
    }
}
