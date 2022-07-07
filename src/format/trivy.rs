use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TrivyMetadata {
    #[serde(rename = "OS")]
    pub os: TrivyOs,
    #[serde(rename = "ImageID")]
    pub image_id: String,
    #[serde(rename = "DiffIDs")]
    pub diff_ids: Vec<String>,
    pub repo_tags: Vec<String>,
    pub repo_digests: Vec<String>,
    pub image_config: ImageConfig,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TrivyOs {
    pub family: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImageConfig {
    pub architecture: String,
    pub created: String,
    pub history: Vec<History>,
    pub os: String,
    pub rootfs: RootFS,
    pub config: Config,
}

fn default_bool() -> bool {
    false
}

#[derive(Debug, Serialize, Deserialize)]
pub struct History {
    pub created: String,
    pub created_by: String,
    pub comment: Option<String>,
    #[serde(default = "default_bool")]
    pub empty_layer: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RootFS {
    pub r#type: String,
    pub diff_ids: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct TrivyJson {
    pub schema_version: u32,
    pub artifact_name: String,
    pub artifact_type: String,
    pub metadata: TrivyMetadata,
    pub results: Vec<TrivyResult>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct TrivyResult {
    pub target: String,
    pub class: String,
    pub r#type: String,
    pub vulnerabilities: Option<Vec<TrivyVulnerability>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct TrivyVulnerability {
    #[serde(rename = "VulnerabilityID")]
    pub vulnerability_id: String,
    pub pkg_name: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub layer: TrivyLayer,
    pub severity_source: Option<String>,
    #[serde(rename = "PrimaryURL")]
    pub primary_url: String,
    pub data_source: TrivyDataSource,
    pub title: Option<String>,
    pub description: String,
    pub severity: String,
    #[serde(rename = "CweIDs")]
    pub cwe_ids: Option<Vec<String>>,
    #[serde(rename = "CVSS")]
    pub cvss: Option<TrivyCvss>,
    pub references: Vec<String>,
    pub published_date: Option<DateTime<Utc>>,
    pub last_modified_date: Option<DateTime<Utc>>,
}

impl TrivyVulnerability {
    pub fn cve_id(&self) -> Option<String> {
        let iter =
            self.vulnerability_id
                .split('-')
                .take(3)
                .collect::<Vec<_>>();
        if iter.len() < 3 {
            return None;
        }
        if iter[0].to_lowercase() != "CVE" {
            return None;
        }
        Some(iter.join("-"))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TrivyLayer {
    #[serde(rename = "DiffID")]
    pub diff_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct TrivyDataSource {
    #[serde(rename = "ID")]
    pub id: String,
    pub name: String,
    #[serde(rename = "URL")]
    pub url: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TrivyCvss {
    pub nvd: Option<CvssScore>,
    pub redhat: Option<CvssScore>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct CvssScore {
    pub v2_vector: Option<String>,
    pub v3_vector: Option<String>,
    pub v2_score: Option<f64>,
    pub v3_score: Option<f64>,
}


#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    pub entrypoint: Vec<String>,
    pub env: Vec<String>,
    pub volumes: BTreeMap<String, BTreeMap<String, String>>,
    pub working_dir: String,
}