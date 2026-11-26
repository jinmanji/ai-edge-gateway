use aws_lc_rs::digest::{SHA256, digest};
use serde::{Deserialize, Deserializer};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::Result;

pub const MAX_KEY_BYTES: usize = 1024;

pub struct Secret(Zeroizing<String>);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(de).map(|s| Self(Zeroizing::new(s)))
    }
}

impl Secret {
    pub fn from_env(name: &str) -> Result<Self> {
        if name.is_empty()
            || name.len() > 128
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err("invalid secret environment variable name".into());
        }
        let value =
            std::env::var(name).map_err(|_| "secret environment variable missing or not UTF-8")?;
        Ok(Self(Zeroizing::new(value)))
    }

    pub fn checked(&self) -> Result<&[u8]> {
        let bytes = self.0.as_bytes();
        if !valid_key(bytes) {
            return Err("invalid credential character or length".into());
        }
        Ok(bytes)
    }
}

// Bearer-compatible ASCII token alphabet. This also prevents header injection.
pub fn valid_key(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.len() <= MAX_KEY_BYTES
        && bytes.iter().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
        })
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn new(key: &[u8]) -> Self {
        let mut bytes = [0; 32];
        bytes.copy_from_slice(digest(&SHA256, key).as_ref());
        Self(bytes)
    }
    pub fn ct_eq(self, other: Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

pub fn load(key: Option<Secret>, env: Option<&str>) -> Result<Secret> {
    match (key, env) {
        (Some(key), None) => Ok(key),
        (None, Some(name)) => Secret::from_env(name),
        _ => Err("specify exactly one of key or key_env".into()),
    }
}
