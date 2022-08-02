
use serde_json::Value;
use crate::model::CvssVersion;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCve {
    pub results_per_page: i64,
    pub start_index: i64,
    pub total_results: i64,
    pub result: NvdResult,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdResult {
    #[serde(rename = "CVE_data_type")]
    pub cve_data_type: String,
    #[serde(rename = "CVE_data_format")]
    pub cve_data_format: String,
    #[serde(rename = "CVE_data_version")]
    pub cve_data_version: String,
    #[serde(rename = "CVE_data_timestamp")]
    pub cve_data_timestamp: String,
    #[serde(rename = "CVE_Items")]
    pub cve_items: Vec<CveItem>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CveItem {
    pub cve: Cve,
    pub configurations: Configurations,
    pub impact: Impact,
    pub published_date: String,
    pub last_modified_date: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cve {
    #[serde(rename = "data_type")]
    pub data_type: String,
    #[serde(rename = "data_format")]
    pub data_format: String,
    #[serde(rename = "data_version")]
    pub data_version: String,
    #[serde(rename = "CVE_data_meta")]
    pub cve_data_meta: CveDataMeta,
    pub problemtype: Problemtype,
    pub references: References,
    pub description: Description2,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CveDataMeta {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "ASSIGNER")]
    pub assigner: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Problemtype {
    #[serde(rename = "problemtype_data")]
    pub problemtype_data: Vec<ProblemtypeDaum>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProblemtypeDaum {
    pub description: Vec<Description>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Description {
    pub lang: String,
    pub value: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct References {
    #[serde(rename = "reference_data")]
    pub reference_data: Vec<ReferenceDaum>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReferenceDaum {
    pub url: String,
    pub name: String,
    pub refsource: String,
    pub tags: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Description2 {
    #[serde(rename = "description_data")]
    pub description_data: Vec<DescriptionDaum>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DescriptionDaum {
    pub lang: String,
    pub value: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Configurations {
    #[serde(rename = "CVE_data_version")]
    pub cve_data_version: String,
    pub nodes: Vec<Node>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub operator: String,
    pub children: Vec<Value>,
    #[serde(rename = "cpe_match")]
    pub cpe_match: Vec<CpeMatch>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CpeMatch {
    pub vulnerable: bool,
    #[serde(rename = "cpe23Uri")]
    pub cpe23uri: String,
    #[serde(rename = "cpe_name")]
    pub cpe_name: Vec<Value>,
    pub version_end_excluding: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Impact {
    pub base_metric_v3: BaseMetricV3,
    pub base_metric_v2: BaseMetricV2,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BaseMetricV3 {
    pub cvss_v3: CvssV3,
    pub exploitability_score: f64,
    pub impact_score: f64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV3 {
    pub version: String,
    pub vector_string: String,
    pub attack_vector: String,
    pub attack_complexity: String,
    pub privileges_required: String,
    pub user_interaction: String,
    pub scope: String,
    pub confidentiality_impact: String,
    pub integrity_impact: String,
    pub availability_impact: String,
    pub base_score: f64,
    pub base_severity: String,
}

impl crate::model::Cvss for CvssV3 {
    fn version(&self) -> Option<CvssVersion> {
        match self.version.as_str() {
            "3.1" => Some(CvssVersion::V3_1),
            "3.0" | "3" => Some(CvssVersion::V3_0),
            _ => None,
        }
    }

    fn vector(&self) -> Option<String> {
        Some(self.vector_string.clone())
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BaseMetricV2 {
    pub cvss_v2: CvssV2,
    pub severity: String,
    pub exploitability_score: f64,
    pub impact_score: f64,
    pub ac_insuf_info: bool,
    pub obtain_all_privilege: bool,
    pub obtain_user_privilege: bool,
    pub obtain_other_privilege: bool,
    pub user_interaction_required: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV2 {
    pub version: String,
    pub vector_string: String,
    pub access_vector: String,
    pub access_complexity: String,
    pub authentication: String,
    pub confidentiality_impact: String,
    pub integrity_impact: String,
    pub availability_impact: String,
    pub base_score: f64,
}
