use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri, header};

#[derive(Clone, Copy, Debug)]
pub struct InvalidHeader;

const HOPS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

fn protected(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "content-length"
            | "authorization"
            | "early-data"
            | "x-api-key"
            | "x-goog-api-key"
            | "x-gateway-key"
    ) || name.starts_with("anthropic-")
        || name.starts_with("openai-")
        || name.starts_with("x-goog-")
        || name.starts_with("sec-websocket-")
}

pub fn request_size(method: &Method, uri: &Uri, h: &HeaderMap) -> usize {
    header_size(h)
        + method.as_str().len()
        + uri.path_and_query().map_or(0, |p| p.as_str().len())
        + uri.authority().map_or(0, |a| a.as_str().len())
        + 4 * 32
        + uri.scheme_str().map_or(0, str::len)
}

pub fn header_size(h: &HeaderMap) -> usize {
    h.iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 32)
        .sum()
}

pub fn has_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
    headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| {
            v.split(',')
                .any(|item| item.trim().eq_ignore_ascii_case(token))
        })
}

pub fn remove_hop(headers: &mut HeaderMap) -> Result<(), InvalidHeader> {
    // Drain all repeated Connection fields, then remove the tokens they nominate.
    // Dropping nominations of framing/auth/vendor headers silently is unsafe.
    if headers.contains_key(header::CONNECTION) {
        let values: Vec<_> = headers
            .get_all(header::CONNECTION)
            .iter()
            .cloned()
            .collect();
        headers.remove(header::CONNECTION);
        for value in values {
            for name in value
                .to_str()
                .map_err(|_| InvalidHeader)?
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| InvalidHeader)?;
                if protected(name.as_str()) {
                    return Err(InvalidHeader);
                }
                headers.remove(name);
            }
        }
    }
    for &name in HOPS {
        headers.remove(name);
    }
    Ok(())
}

pub fn remove_forwarding(headers: &mut HeaderMap) {
    for name in [
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-forwarded-proto",
        "x-real-ip",
    ] {
        headers.remove(name);
    }
}

pub fn trailers(headers: &mut HeaderMap, max: usize) -> Result<(), InvalidHeader> {
    if header_size(headers) > max {
        return Err(InvalidHeader);
    }
    remove_hop(headers)?;
    let prohibited: Vec<_> = headers
        .keys()
        .filter(|n| {
            protected(n.as_str())
                || matches!(
                    n.as_str(),
                    "cookie"
                        | "set-cookie"
                        | "content-type"
                        | "content-encoding"
                        | "content-range"
                        | "alt-svc"
                        | "location"
                        | "cache-control"
                )
        })
        .cloned()
        .collect();
    for name in prohibited {
        headers.remove(name);
    }
    Ok(())
}

pub fn content_length(headers: &HeaderMap) -> Result<Option<u64>, InvalidHeader> {
    single(headers, header::CONTENT_LENGTH)?
        .map(|v| {
            let v = v.to_str().map_err(|_| InvalidHeader)?;
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(InvalidHeader);
            }
            v.parse().map_err(|_| InvalidHeader)
        })
        .transpose()
}

pub fn single(
    headers: &HeaderMap,
    name: HeaderName,
) -> Result<Option<&HeaderValue>, InvalidHeader> {
    let mut values = headers.get_all(name).into_iter();
    let v = values.next();
    if values.next().is_some() {
        return Err(InvalidHeader);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_all_nominations_but_preserves_vendor_headers() {
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("connection", "some-hop"),
            ("connection", "upgrade, another-hop"),
            ("some-hop", "private"),
            ("another-hop", "private"),
            ("upgrade", "h2c"),
            ("te", "trailers"),
            ("anthropic-version", "2023-06-01"),
            ("anthropic-beta", "some-beta"),
        ] {
            h.append(HeaderName::from_static(k), HeaderValue::from_static(v));
        }
        remove_hop(&mut h).unwrap();
        assert_eq!(h.len(), 2);
        h.insert(
            header::CONNECTION,
            HeaderValue::from_static("Anthropic-Version"),
        );
        assert!(remove_hop(&mut h).is_err());
    }
}
