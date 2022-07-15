use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::{Cvss, v3_1};
use crate::context::CvssProvider;
use crate::format::{VulnerabilityFormat, VulnId};
use crate::model::{CvssVector, CvssVersion};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TrivyMetadata {
    #[serde(rename = "OS")]
    pub os: Option<TrivyOs>,
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
pub struct Trivy {
    pub schema_version: u32,
    pub artifact_name: String,
    pub artifact_type: String,
    pub metadata: TrivyMetadata,
    pub results: Option<Vec<TrivyResult>>,
}

impl CvssProvider for TrivyVulnerability {
    fn cvss_v3_1(&self) -> Option<v3_1::BaseMetric> {
        self.cvss.as_ref()
            .and_then(|v| v.vector())
            .and_then(|v| v3_1::BaseMetric::from_vector_string(&v))
    }
}

impl VulnerabilityFormat for Trivy {
    fn cvss_v3_1_scores(&self) -> BTreeMap<VulnId, v3_1::BaseMetric> {
        let results = match self.results.as_ref() {
            None => return BTreeMap::new(),
            Some(results) => results,
        };
        results
            .iter()
            .filter_map(|result| result.vulnerabilities.as_ref())
            .flatten()
            .filter_map(|v| {
                let id = VulnId::try_from(v.vulnerability_id.clone()).ok()?;
                let score = v.cvss_v3_1()?;
                Some((id, score))
            })
            .collect()
    }
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
    pub primary_url: Option<String>,
    pub data_source: TrivyDataSource,
    pub title: Option<String>,
    pub description: Option<String>,
    pub severity: String,
    #[serde(rename = "CweIDs")]
    pub cwe_ids: Option<Vec<String>>,
    #[serde(rename = "CVSS")]
    pub cvss: Option<TrivyCvss>,
    pub references: Option<Vec<String>>,
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
        if iter.len() != 3 {
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

#[derive(Serialize, Deserialize, Debug, PartialEq, PartialOrd)]
pub struct TrivyCvss {
    pub nvd: Option<CvssScore>,
    pub redhat: Option<CvssScore>,
}

impl Cvss for TrivyCvss {
    fn version(&self) -> Option<CvssVersion> {
        self.nvd.as_ref().and_then(|v| v.version())
            .or(self.redhat.as_ref().and_then(|v| v.version()))
    }

    fn vector(&self) -> Option<String> {
        self.nvd.as_ref().and_then(|v| v.vector())
            .or(self.redhat.as_ref().and_then(|v| v.vector()))
    }

    fn as_vector(&self) -> Option<CvssVector> {
        self.nvd.as_ref().and_then(|v| v.as_vector())
            .or(self.redhat.as_ref().and_then(|v| v.as_vector()))
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, PartialOrd)]
#[serde(rename_all = "PascalCase")]
pub struct CvssScore {
    pub v2_vector: Option<String>,
    pub v3_vector: Option<String>,
    pub v2_score: Option<f64>,
    pub v3_score: Option<f64>,
}

impl Cvss for CvssScore {
    fn version(&self) -> Option<CvssVersion> {
        if let Some(vec) = &self.v3_vector {
            let mut split = vec.split(':');
            let first = split.next();
            if let Some(first) = first {
                return match first {
                    "CVSS:3.1" => Some(CvssVersion::V3_1),
                    "CVSS:3.0" => Some(CvssVersion::V3_0),
                    _ => None,
                };
            }
        }

        self.v2_vector.as_ref().map(|_| CvssVersion::V2_0)
    }

    fn vector(&self) -> Option<String> {
        self.v3_vector.as_ref()
            .or(self.v2_vector.as_ref())
            .cloned()
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    pub entrypoint: Option<Vec<String>>,
    pub env: Vec<String>,
    pub volumes: Option<BTreeMap<String, BTreeMap<String, String>>>,
    pub working_dir: Option<String>,
}