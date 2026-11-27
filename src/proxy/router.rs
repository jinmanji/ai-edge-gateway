use std::{borrow::Cow, sync::Arc};

use bytes::Bytes;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version, header,
    uri::{Authority, PathAndQuery},
};
use zeroize::Zeroizing;

use super::headers;
use crate::{
    config::{Mode, Provider, Snapshot, secret::valid_key},
    pool::Pool,
};

const GATEWAY: HeaderName = HeaderName::from_static("x-gateway-key");
const CLAUDE: HeaderName = HeaderName::from_static("x-api-key");
const GEMINI: HeaderName = HeaderName::from_static("x-goog-api-key");

#[derive(Debug)]
pub struct Rejection(pub StatusCode, pub &'static str);
fn malformed() -> Rejection {
    Rejection(
        StatusCode::BAD_REQUEST,
        "ambiguous or malformed request credentials\n",
    )
}
fn unauthorized() -> Rejection {
    Rejection(
        StatusCode::UNAUTHORIZED,
        "credential missing or not authorized\n",
    )
}
fn not_found() -> Rejection {
    Rejection(StatusCode::NOT_FOUND, "no provider route\n")
}

pub struct Routed {
    pub pool: Arc<Pool>,
    pub target: Uri,
}

pub async fn route(
    snapshot: &Snapshot,
    method: &Method,
    version: Version,
    uri: &Uri,
    headers: &mut HeaderMap,
    websocket: bool,
) -> Result<Routed, Rejection> {
    if method == Method::CONNECT || method == Method::TRACE {
        return Err(Rejection(
            StatusCode::METHOD_NOT_ALLOWED,
            "method not supported\n",
        ));
    }
    if matches!(version, Version::HTTP_10 | Version::HTTP_11)
        && (uri.scheme().is_some() || uri.authority().is_some())
    {
        return Err(Rejection(
            StatusCode::BAD_REQUEST,
            "origin-form request target required\n",
        ));
    }
    let input = uri.path_and_query().ok_or_else(not_found)?;
    let (provider, strip) = select(snapshot, input.path(), uri.authority(), headers)?;
    let path = &input.path()[strip..];
    if !path.starts_with('/') {
        return Err(not_found());
    }
    let route = &snapshot.routes[provider.index()];
    if route.mode == Mode::Disabled {
        return Err(not_found());
    }
    let query = input.query();
    let mut query_key = None;
    let compatible = path.starts_with("/v1beta/openai/");
    if provider == Provider::Gemini {
        query_key = find_key(query)?;
    }
    let gateway = headers::single(headers, GATEWAY).map_err(|_| malformed())?;
    let auth = headers::single(headers, header::AUTHORIZATION).map_err(|_| malformed())?;
    let claude = headers::single(headers, CLAUDE).map_err(|_| malformed())?;
    let gemini = headers::single(headers, GEMINI).map_err(|_| malformed())?;
    let count = usize::from(auth.is_some())
        + usize::from(claude.is_some())
        + usize::from(gemini.is_some())
        + usize::from(query_key.is_some());
    if count + usize::from(gateway.is_some()) > 1
        || (gateway.is_some() && route.mode != Mode::Managed)
    {
        return Err(malformed());
    }
    let (form, user_key) = if let Some(value) = gateway {
        let form = match provider {
            Provider::Openai => Form::Bearer,
            Provider::Claude => Form::Claude,
            Provider::Gemini if compatible => Form::Bearer,
            Provider::Gemini if websocket => Form::Query,
            Provider::Gemini => Form::Gemini,
        };
        (form, value.as_bytes())
    } else {
        match provider {
            Provider::Openai => (Form::Bearer, parse_bearer(auth.ok_or_else(unauthorized)?)?),
            Provider::Claude => (Form::Claude, claude.ok_or_else(unauthorized)?.as_bytes()),
            Provider::Gemini if query_key.is_some() => (
                Form::Query,
                query_key.as_ref().ok_or_else(malformed)?.value.as_slice(),
            ),
            Provider::Gemini if gemini.is_some() => {
                (Form::Gemini, gemini.ok_or_else(malformed)?.as_bytes())
            }
            Provider::Gemini if compatible => {
                (Form::Bearer, parse_bearer(auth.ok_or_else(unauthorized)?)?)
            }
            Provider::Gemini => return Err(unauthorized()),
        }
    };
    if !valid_key(user_key) {
        return Err(malformed());
    }

    let (pool, inject) = match route.mode {
        Mode::Managed => {
            let grant = snapshot
                .authenticate(user_key, provider)
                .ok_or_else(unauthorized)?;
            if !grant.permits(method, path) {
                return Err(Rejection(
                    StatusCode::FORBIDDEN,
                    "method or path not in grant\n",
                ));
            }
            (
                grant.upstream.pool.clone(),
                Some(grant.upstream.key.checked().map_err(|_| {
                    Rejection(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "gateway credential invalid\n",
                    )
                })?),
            )
        }
        Mode::Byok => {
            if snapshot.is_user_key(user_key) {
                return Err(unauthorized());
            }
            let egress = route.byok_egress.as_ref().ok_or_else(not_found)?;
            let stats = snapshot
                .metrics
                .get(&(provider, egress.name.clone()))
                .cloned()
                .ok_or_else(not_found)?;
            let pool = snapshot
                .byok
                .get(
                    &snapshot.factory,
                    provider,
                    egress,
                    user_key,
                    stats,
                    route.prefer_h3,
                )
                .await
                .map_err(|_| {
                    Rejection(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "upstream isolation capacity unavailable\n",
                    )
                })?;
            (pool, None)
        }
        Mode::Disabled => return Err(not_found()),
    };
    let replacement = if let (Form::Query, Some(key)) = (form, inject) {
        Some(replace_query_key(
            path,
            query,
            query_key.as_ref().map(|k| k.index),
            key,
        )?)
    } else {
        None
    };
    let target = match replacement {
        Some(p) => p,
        None if strip == 0 => input.clone(),
        None => PathAndQuery::try_from(&input.as_str()[strip..])
            .map_err(|_| Rejection(StatusCode::BAD_REQUEST, "invalid provider path\n"))?,
    };

    headers.remove(GATEWAY);
    if let Some(key) = inject {
        headers.remove(header::AUTHORIZATION);
        headers.remove(CLAUDE);
        headers.remove(GEMINI);
        let name = match form {
            Form::Bearer => Some(header::AUTHORIZATION),
            Form::Claude => Some(CLAUDE),
            Form::Gemini => Some(GEMINI),
            Form::Query => None,
        };
        if let Some(name) = name {
            let mut val = if matches!(form, Form::Bearer) {
                let mut temp = Zeroizing::new(Vec::with_capacity(7 + key.len()));
                temp.extend_from_slice(b"Bearer ");
                temp.extend_from_slice(key);
                HeaderValue::from_bytes(&temp)
            } else {
                HeaderValue::from_bytes(key)
            }
            .map_err(|_| malformed())?;
            val.set_sensitive(true);
            headers.insert(name, val);
        }
    } else {
        for name in [header::AUTHORIZATION, CLAUDE, GEMINI] {
            if let Some(val) = headers.get_mut(name) {
                val.set_sensitive(true);
            }
        }
    }
    // Preserve only the official URI authority. The H1 transport will add
    // Host; HTTP/2 uses :authority without a duplicate Host field.
    headers.remove(header::HOST);
    let target = pool
        .origin()
        .uri(target)
        .map_err(|_| Rejection(StatusCode::BAD_REQUEST, "invalid provider path\n"))?;
    Ok(Routed { pool, target })
}

fn select(
    snapshot: &Snapshot,
    path: &str,
    authority: Option<&Authority>,
    headers: &HeaderMap,
) -> Result<(Provider, usize), Rejection> {
    let prefix = [
        (Provider::Openai, "/openai/"),
        (Provider::Claude, "/claude/"),
        (Provider::Gemini, "/gemini/"),
    ]
    .into_iter()
    .find_map(|(p, s)| path.starts_with(s).then_some((p, s.len() - 1)));
    let host = headers::single(headers, header::HOST)
        .map_err(|_| Rejection(StatusCode::BAD_REQUEST, "duplicate host\n"))?;
    let host = host
        .map(|v| {
            Authority::try_from(v.as_bytes())
                .map_err(|_| Rejection(StatusCode::BAD_REQUEST, "invalid host\n"))
        })
        .transpose()?;
    if let (Some(a), Some(h)) = (authority, &host)
        && !a.as_str().eq_ignore_ascii_case(h.as_str())
    {
        return Err(Rejection(StatusCode::BAD_REQUEST, "conflicting host\n"));
    }
    let host = authority.or(host.as_ref()).map(Authority::host);
    let subdomain = host.and_then(|host| {
        Provider::ALL.into_iter().find(|p| {
            snapshot.routes[p.index()]
                .host
                .as_deref()
                .is_some_and(|expected| expected.eq_ignore_ascii_case(host))
        })
    });
    match (prefix, subdomain) {
        (Some((by_path, _)), Some(by_host)) if by_path != by_host => Err(Rejection(
            StatusCode::MISDIRECTED_REQUEST,
            "conflicting provider routes\n",
        )),
        (Some(route), _) => Ok(route),
        (None, Some(provider)) => Ok((provider, 0)),
        (None, None) => Err(not_found()),
    }
}

fn parse_bearer(value: &HeaderValue) -> Result<&[u8], Rejection> {
    let bytes = value.as_bytes();
    if bytes
        .get(..7)
        .is_none_or(|b| !b.eq_ignore_ascii_case(b"Bearer "))
    {
        return Err(malformed());
    }
    Ok(&bytes[7..])
}

#[derive(Clone, Copy)]
enum Form {
    Bearer,
    Claude,
    Gemini,
    Query,
}
struct QueryKey {
    index: usize,
    value: Zeroizing<Vec<u8>>,
}

fn find_key(query: Option<&str>) -> Result<Option<QueryKey>, Rejection> {
    let Some(query) = query else { return Ok(None) };
    let mut found = None;
    for (i, part) in query.split('&').enumerate() {
        let (name, value) = part.split_once('=').unwrap_or((part, ""));
        // Decode only a three-byte name candidate; leave all other pairs as received.
        if !(3..=9).contains(&name.len()) {
            continue;
        }
        let name = match decode(name) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if name.as_ref() != b"key" {
            continue;
        }
        if found.is_some() {
            return Err(malformed());
        }
        if value.len() > crate::config::secret::MAX_KEY_BYTES * 3 {
            return Err(malformed());
        }
        let value = decode(value)?.into_owned();
        found = Some(QueryKey {
            index: i,
            value: Zeroizing::new(value),
        });
    }
    Ok(found)
}

fn decode(s: &str) -> Result<Cow<'_, [u8]>, Rejection> {
    let bytes = s.as_bytes();
    if !bytes.iter().any(|b| matches!(b, b'%' | b'+')) {
        return Ok(Cow::Borrowed(bytes));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut it = bytes.iter().copied();
    while let Some(b) = it.next() {
        out.push(match b {
            b'%' => {
                let a = it.next().and_then(hex).ok_or_else(malformed)?;
                let b = it.next().and_then(hex).ok_or_else(malformed)?;
                a * 16 + b
            }
            b'+' => b' ',
            b => b,
        });
    }
    Ok(Cow::Owned(std::mem::take(&mut *out)))
}
fn hex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|v| v as u8)
}

fn replace_query_key(
    path: &str,
    query: Option<&str>,
    key_index: Option<usize>,
    key: &[u8],
) -> Result<PathAndQuery, Rejection> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let write_key = |out: &mut Vec<u8>| {
        out.extend_from_slice(b"key=");
        for &b in key {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                out.push(b);
            } else {
                out.extend_from_slice(&[b'%', HEX[(b >> 4) as usize], HEX[(b & 15) as usize]]);
            }
        }
    };
    let mut out = Zeroizing::new(Vec::with_capacity(
        path.len() + query.map_or(0, str::len) + key.len() * 3 + 6,
    ));
    out.extend_from_slice(path.as_bytes());
    out.push(b'?');
    if let Some(q) = query {
        if let Some(index) = key_index {
            for (i, part) in q.split('&').enumerate() {
                if i != 0 {
                    out.push(b'&');
                }
                if i == index {
                    write_key(&mut out);
                } else {
                    out.extend_from_slice(part.as_bytes());
                }
            }
        } else {
            if !q.is_empty() {
                out.extend_from_slice(q.as_bytes());
                out.push(b'&');
            }
            write_key(&mut out);
        }
    } else {
        write_key(&mut out);
    }
    PathAndQuery::from_maybe_shared(Bytes::from(std::mem::take(&mut *out))).map_err(|_| malformed())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn query_key_rewrite_does_not_reencode_any_other_pair() {
        let q = "a=%2f&&%6bey=user%2btoken&alt=sse&keyname=K+L&Key=ok&";
        let k = find_key(Some(q)).unwrap().unwrap();
        assert_eq!(k.value.as_slice(), b"user+token");
        let actual =
            replace_query_key("/v1/models", Some(q), Some(k.index), b"official+/=").unwrap();
        assert_eq!(
            actual.as_str(),
            "/v1/models?a=%2f&&key=official%2B%2F%3D&alt=sse&keyname=K+L&Key=ok&"
        );
        assert!(find_key(Some("key=a&%6B%65%79=b")).is_err());
        assert!(find_key(Some("key=%XX")).is_err());
        assert!(find_key(Some("somekey=a&Key=b")).unwrap().is_none());
    }
}
