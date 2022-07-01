#![allow(dead_code)]

use std::fmt::{Display, Formatter};
use std::str::FromStr;
use reqwest::{Client};
use reqwest::header::{HeaderMap, HeaderValue};

pub struct NvdApi(Client);

// CVE-2012-1093
pub struct CveId {
    year: u16,
    id: u32,
}

pub enum CveIdError {
    InvalidYear,
    InvalidId,
}

impl TryFrom<String> for CveId {
    type Error = CveIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut parts = value.split('-');
        let _ = parts.next();
        let year = parts.next()
            .ok_or(())
            .and_then(|year| u16::from_str(year).map_err(|_| ()))
            .map_err(|_| CveIdError::InvalidYear)?;
        let id = parts.next()
            .ok_or(())
            .and_then(|id| u32::from_str(id).map_err(|_| ()))
            .map_err(|_| CveIdError::InvalidId)?;
        Ok(Self { year, id })
    }
}

impl Display for CveId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "CVE-{}-{}", self.year, self.id)
    }
}

pub enum Error {
    Web(reqwest::Error),
    Json(serde_json::Error),
}

impl NvdApi {
    pub fn new(api_key: String) -> Option<Self> {
        let mut headers = HeaderMap::new();
        headers.insert("X-ApiKey", HeaderValue::from_str(&api_key).ok()?);

        Client::builder()
            .default_headers(headers)
            .build()
            .ok()
            .map(|v| Self(v))
    }
}