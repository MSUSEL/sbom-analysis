#![allow(dead_code)]

use std::fmt::{Display, Formatter};
use std::str::FromStr;
use reqwest::{Client, Error};
use reqwest::header::{HeaderMap, HeaderValue};

pub struct NvdApi(Client);

// CVE-2012-1093
pub struct CveId {
    year: u16,
    id: u32,
}

impl TryFrom<String> for CveId {
    type Error = ();

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut parts = value.split('-');
        let _ = parts.next();
        let year = u16::from_str(parts.next().ok_or(())?).map_err(|_| ())?;
        let id = u32::from_str(parts.next().ok_or(())?).map_err(|_| ())?;
        Ok(Self { year, id })
    }
}

impl Display for CveId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "CVE-{}-{}", self.year, self.id)
    }
}

enum Issue {
    Web(Error),
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

    async fn get_cve(&self, _cve_id: CveId) -> Result<CveId, Issue> {
        // serde_json::from_str(&self.0
        //     .get(&format!("https://nvd.nist.gov/vuln/detail/{}", cve_id))
        //     .send()
        //     .await
        //     .map_err(|e| Issue::Web(e))?
        //     // .text().await.map_err(|e| Issue::Web(e))?)
        //     .map_err(|e| Issue::Json(e))
        todo!()
    }
}