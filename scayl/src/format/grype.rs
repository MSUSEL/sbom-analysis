use std::collections::BTreeMap;
use std::path::PathBuf;
use serde_json::Value;
use crate::{Cvss, v3_1};
use crate::context::CvssProvider;
use crate::format::{VulnerabilityFormat, VulnId};
use crate::model::CvssVersion;

#[derive(Debug, Serialize, Deserialize)]
pub struct Grype {
    pub matches: Vec<Match>,
    pub source: Source,
    pub distro: Distro,
    pub descriptor: Descriptor,
}

pub struct GrypeFileFilter;
impl crate::RecurseDir<()> for GrypeFileFilter {
    fn matches(&self, path: &PathBuf) -> Option<()> {
        path.file_name()
            .map(|v| v.to_string_lossy().to_string())
            .filter(|v| v == "grype.json")
            .map(|_| ())
    }
}

impl VulnerabilityFormat for Grype {
    fn cvss_v3_1_scores(&self) -> BTreeMap<VulnId, v3_1::BaseMetric> {
        self.matches.iter().filter_map(|v| {
            let id = VulnId::try_from(v.vulnerability.id.clone()).ok()?;
            let metric = v.vulnerability.cvss_v3_1()?;
            Some((id, metric))
        }).collect()
    }
}

impl CvssProvider for Vulnerability {
    fn cvss_v3_1(&self) -> Option<v3_1::BaseMetric> {
        self.cvss.iter()
            .filter(|cvss| cvss.version == "3.1")
            .map(|cvss| cvss.vector.split('/'))
            .filter_map(|mut v| {
                v.next(); // Skip the version
                let map = BTreeMap::from_iter(v
                    .map(|v| v.split(':'))
                    .map(|mut v| (v.next(), v.next()))
                    .filter_map(|(a, b)| a.and_then(|a| b.map(|b| (a, b))))
                );

                use crate::cvss::{FromVector, v3_1::*};

                BaseMetric::from_vector(&map)
            }).next()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Match {
    pub vulnerability: Vulnerability,
    pub related_vulnerabilities: Vec<Vulnerability>,
    pub match_details: Vec<MatchDetails>,
    pub artifact: Artifact,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerability {
    pub id: String,
    pub data_source: String,
    pub namespace: String,
    pub severity: String,
    pub urls: Vec<String>,
    pub cvss: Vec<GrypeCvss>,
    pub fix: Option<Fix>,
    pub description: Option<String>,
    pub advisories: Option<Vec<Advisory>>,
}

impl Vulnerability {
    pub fn cve_id(&self) -> Option<String> {
        let split = self.id.split('-')
            .take(3)
            .collect::<Vec<_>>();
        if split.len() != 3 || split[0].to_lowercase() != "cve" {
            return None;
        }
        return Some(split.join("-"));
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GrypeCvss {
    pub version: String,
    pub vector: String,
    pub metrics: Metrics,
    pub vendor_metadata: Value,
}

impl Cvss for GrypeCvss {
    fn version(&self) -> Option<CvssVersion> {
        <&GrypeCvss as Cvss>::version(&self)
    }

    fn vector(&self) -> Option<String> {
        <&GrypeCvss as Cvss>::vector(&self)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Metrics {
    pub base_score: f64,
    pub exploitability_score: f64,
    pub impact_score: f64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FixState {
    NotFixed,
    Fixed,
    Unknown,
    WontFix,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fix {
    pub versions: Vec<String>,
    pub state: FixState,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Advisory {
    pub uri: Option<String>,
    pub id: Option<String>,
    pub link: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MatchDetails {
    pub r#type: String,
    pub matcher: String,
    pub searched_by: SearchedBy,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchedBy {
    pub distro: Option<MatchDistro>,
    pub namespace: String,
    pub cpes: Option<Vec<String>>,
    pub package: Option<MatchPackage>,
    pub found: Option<Found>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MatchDistro {
    r#type: String,
    version: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MatchPackage {
    name: String,
    version: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Found {
    pub version_constraint: String,
    pub cpes: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Artifact {
    pub name: String,
    pub version: String,
    pub r#type: String,
    pub locations: Vec<Location>,
    pub language: String,
    pub licenses: Vec<String>,
    pub cpes: Vec<String>,
    pub purl: String,
    pub upstreams: Vec<Upstream>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    pub path: String,
    #[serde(rename = "layerID")]
    pub layer_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Upstream {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    pub r#type: String,
    pub target: Target,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    pub user_input: String,
    #[serde(rename = "imageID")]
    pub image_id: String,
    pub manifest_digest: String,
    pub media_type: String,
    pub tags: Vec<String>,
    pub image_size: u64,
    pub layers: Vec<Layer>,
    pub manifest: String,
    pub config: String,
    pub repo_digests: Vec<String>,
    pub architecture: String,
    pub os: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Layer {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Distro {
    pub name: String,
    pub version: String,
    pub id_like: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    pub name: String,
    pub version: String,
    pub configuration: Configuration,
    pub db: Db,
}


#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Configuration {
    pub config_path: Option<String>,
    pub output: String,
    pub file: String,
    pub distro: String,
    pub add_cpes_if_none: bool,
    pub output_template_file: String,
    pub quiet: bool,
    pub check_for_app_update: bool,
    pub only_fixed: bool,
    pub platform: String,
    pub search: Search,
    pub ignore: Option<()>,
    pub exclude: Vec<String>,
    pub db: GrypeDb,
    pub external_sources: Option<ExternalSources>,
    pub dev: Dev,
    pub fail_on_severity: String,
    pub registry: Registry,
    pub log: Log,
    pub attestation: Attestation,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Search {
    pub scope: String,
    pub unindexed_archives: bool,
    pub indexed_archives: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GrypeDb {
    pub cache_dir: String,
    pub update_url: String,
    pub ca_cert: String,
    pub auto_update: bool,
    pub validate_by_hash_on_start: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExternalSources {
    pub enable: bool,
    pub maven: Maven,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Maven {
    pub search_upstream_by_sha_1: bool,
    pub base_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Dev {
    pub profile_cpu: bool,
    pub profile_mem: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Registry {
    pub insecure_skip_tls_verify: bool,
    pub insecure_use_http: bool,
    pub auth: Vec<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Log {
    pub structured: bool,
    pub level: String,
    pub file: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Attestation {
    pub public_key: String,
    pub skip_verification: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Db {
    pub built: String,
    pub schema_version: u32,
    pub location: String,
    pub checksum: String,
    pub error: Option<Value>,
}
