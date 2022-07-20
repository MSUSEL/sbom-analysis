#![allow(dead_code)]

pub struct VtApi(reqwest::Client);

impl VtApi {
    pub fn new(client: reqwest::Client) -> Self {
        Self(client)
    }

    pub async fn file_info(&self, sha256: String) -> Result<String, reqwest::Error> {
        let res = self.0
            .get(&format!("https://www.virustotal.com/api/v3/monitor_partner/hashes/{}/items", sha256))
            .header("x-apikey", std::env::var("VT_API_KEY").expect("VT_API_KEY is not set"))
            .send()
            .await?;
        res.text().await
    }

    pub async fn file_report(&self, hash: String) -> Result<String, reqwest::Error> {
        let res = self.0
            .get(&format!("https://www.virustotal.com/api/v3/files/{}", hash))
            .header("x-apikey", std::env::var("VT_API_KEY").expect("VT_API_KEY is not set"))
            .send()
            .await?;
        res.text().await
    }
}