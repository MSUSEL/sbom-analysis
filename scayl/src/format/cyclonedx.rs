use std::cmp::Ordering;
use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::{Cvss, CvssProvider, CvssVersion, FromVector, VulnerabilityFormat, VulnId};
use crate::v3_1::BaseMetric;

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDx {
    pub bom_format: String,
    pub spec_version: String,
    pub serial_number: String,
    pub version: u32,
    pub metadata: Metadata,
    pub components: Vec<Component>,
    pub dependencies: Vec<Dependency>,
    pub vulnerabilities: Vec<Vulnerability>,
}

impl VulnerabilityFormat for CycloneDx {
    fn cvss_v3_1_scores(&self) -> BTreeMap<VulnId, BaseMetric> {
        self.vulnerabilities
            .iter()
            .filter_map(|v| {
                let score = v.cvss_v3_1()?;
                let id = VulnId::try_from(v.id.clone()).ok()?;
                Some((id, score))
            })
            .collect()
    }
}

impl CvssProvider for Vulnerability {
    fn cvss_v3_1(&self) -> Option<BaseMetric> {
        self.ratings
            .iter()
            .filter_map(|v| {
                v.iter()
                    .find(|v| {
                        if let Some(CvssVersion::V3_1) = v.version() {
                            true
                        } else {
                            false
                        }
                    })
                    .and_then(|v| {
                        v.as_vector()
                    })
                    .and_then(|v| BaseMetric::from_vector_string(&v.vector))
            })
            .next()
    }
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub timestamp: DateTime<Utc>,
    pub tools: Vec<Tool>,
    pub component: Component,
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub vendor: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Component {
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub name: String,
    pub purl: Option<String>,
    pub properties: Vec<Property>,
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Property {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dependency {
    #[serde(rename = "ref")]
    pub ref_: String,
    pub depends_on: Vec<String>,
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerability {
    pub id: String,
    pub source: Source,
    pub ratings: Option<Vec<Rating>>,
    pub description: String,
    pub advisories: Vec<Advisory>,
    pub affects: Vec<Affected>,
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialOrd, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rating {
    pub source: RatingSource,
    pub score: Option<f32>,
    pub severity: Severity,
    pub method: Option<String>,
    pub vector: Option<String>,
}

impl Ord for Rating {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap_or(Ordering::Equal)
    }
}

impl Eq for Rating {}

impl Cvss for Rating {
    fn version(&self) -> Option<CvssVersion> {
        self.method.as_ref().and_then(|vec| match vec.as_str() {
            "CVSSv31" => Some(CvssVersion::V3_1),
            "CVSSv30" => Some(CvssVersion::V3_0),
            "CVSSv20" => Some(CvssVersion::V2_0),
            _ => None,
        })
    }

    fn vector(&self) -> Option<String> {
        self.vector.as_ref().cloned()
    }
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RatingSource {
    pub name: String,
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Advisory {
    pub url: String,
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Affected {
    #[serde(rename = "ref")]
    pub ref_: String,
    pub versions: Vec<Version>,
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    pub version: String,
    pub status: Status,
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    Affected,
}



