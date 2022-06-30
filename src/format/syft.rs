// use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct Syft {
    #[serde(rename = "artifactRelationships")]
    pub artifact_relationships: Vec<Relationship>,
    pub artifacts: Vec<Package>,
    pub descriptor: Descriptor,
    pub distro: LinuxRelease,
    pub files: Option<Vec<File>>,
    pub schema: Schema,
    pub secrets: Option<Vec<Secrets>>,
    pub source: Source,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Relationship {
    pub child: String,
    pub metadata: Option<ConfigurationUnion>,
    pub parent: String,
    #[serde(rename = "type")]
    pub relationship_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Package {
    pub cpes: Vec<String>,
    #[serde(rename = "foundBy")]
    pub found_by: String,
    pub id: String,
    pub language: String,
    pub licenses: Vec<String>,
    pub locations: Vec<Coordinates>,
    pub metadata: Option<Metadata>,
    #[serde(rename = "metadataType")]
    pub metadata_type: Option<String>,
    pub name: String,
    pub purl: String,
    #[serde(rename = "type")]
    pub package_type: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Coordinates {
    #[serde(rename = "layerID")]
    pub layer_id: Option<String>,
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    pub architecture: Option<String>,
    pub description: Option<String>,
    pub files: Option<Vec<FileUnion>>,
    #[serde(rename = "gitCommitOfApkPort")]
    pub git_commit_of_apk_port: Option<String>,
    #[serde(rename = "installedSize")]
    pub installed_size: Option<i64>,
    pub license: Option<License>,
    pub maintainer: Option<String>,
    #[serde(rename = "originPackage")]
    pub origin_package: Option<String>,
    pub package: Option<String>,
    #[serde(rename = "pullChecksum")]
    pub pull_checksum: Option<String>,
    #[serde(rename = "pullDependencies")]
    pub pull_dependencies: Option<String>,
    pub size: Option<i64>,
    pub url: Option<String>,
    pub version: Option<String>,
    pub checksum: Option<String>,
    pub dependencies: Option<Vec<String>>,
    pub name: Option<String>,
    pub source: Option<SourceUnion>,
    pub hosted_url: Option<String>,
    pub vcs_url: Option<String>,
    #[serde(rename = "hashPath")]
    pub hash_path: Option<String>,
    pub path: Option<String>,
    pub sha512: Option<String>,
    #[serde(rename = "sourceVersion")]
    pub source_version: Option<String>,
    pub authors: Option<Vec<Author>>,
    pub homepage: Option<String>,
    pub licenses: Option<Vec<String>>,
    #[serde(rename = "goBuildSettings")]
    pub go_build_settings: Option<HashMap<String, String>>,
    #[serde(rename = "goCompiledVersion")]
    pub go_compiled_version: Option<String>,
    #[serde(rename = "h1Digest")]
    pub h1_digest: Option<String>,
    #[serde(rename = "mainModule")]
    pub main_module: Option<String>,
    pub digest: Option<Vec<Digest>>,
    pub manifest: Option<JavaManifest>,
    #[serde(rename = "pomProject")]
    pub pom_project: Option<PomProject>,
    #[serde(rename = "pomProperties")]
    pub pom_properties: Option<PomProperties>,
    #[serde(rename = "virtualPath")]
    pub virtual_path: Option<String>,
    pub author: Option<String>,
    pub bin: Option<Vec<String>>,
    pub dist: Option<PhpComposerExternalReference>,
    pub keywords: Option<Vec<String>>,
    #[serde(rename = "notification-url")]
    pub notification_url: Option<String>,
    pub provide: Option<HashMap<String, String>>,
    pub require: Option<HashMap<String, String>>,
    #[serde(rename = "require-dev")]
    pub require_dev: Option<HashMap<String, String>>,
    pub suggest: Option<HashMap<String, String>>,
    pub time: Option<String>,
    #[serde(rename = "type")]
    pub metadata_type: Option<String>,
    #[serde(rename = "authorEmail")]
    pub author_email: Option<String>,
    #[serde(rename = "directUrlOrigin")]
    pub direct_url_origin: Option<PythonDirectUrlOriginInfo>,
    pub platform: Option<String>,
    #[serde(rename = "sitePackagesRootPath")]
    pub site_packages_root_path: Option<String>,
    #[serde(rename = "topLevelPackages")]
    pub top_level_packages: Option<Vec<String>>,
    pub epoch: Option<i64>,
    pub release: Option<String>,
    #[serde(rename = "sourceRpm")]
    pub source_rpm: Option<String>,
    pub vendor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PhpComposerAuthors {
    pub email: Option<String>,
    pub homepage: Option<String>,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Digest {
    pub algorithm: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PythonDirectUrlOriginInfo {
    #[serde(rename = "commitId")]
    pub commit_id: Option<String>,
    pub url: String,
    pub vcs: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PhpComposerExternalReference {
    pub reference: String,
    pub shasum: Option<String>,
    #[serde(rename = "type")]
    pub php_composer_external_reference_type: String,
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileRecord {
    pub digest: Option<PurpleDigest>,
    #[serde(rename = "ownerGid")]
    pub owner_gid: Option<String>,
    #[serde(rename = "ownerUid")]
    pub owner_uid: Option<String>,
    pub path: String,
    pub permissions: Option<String>,
    #[serde(rename = "isConfigFile")]
    pub is_config_file: Option<bool>,
    pub size: Option<Size>,
    pub flags: Option<String>,
    #[serde(rename = "groupName")]
    pub group_name: Option<String>,
    pub mode: Option<i64>,
    #[serde(rename = "userName")]
    pub user_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PurpleDigest {
    pub algorithm: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JavaManifest {
    pub main: Option<HashMap<String, String>>,
    #[serde(rename = "namedSections")]
    pub named_sections: Option<HashMap<String, HashMap<String, String>>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PomProject {
    #[serde(rename = "artifactId")]
    pub artifact_id: String,
    pub description: Option<String>,
    #[serde(rename = "groupId")]
    pub group_id: String,
    pub name: String,
    pub parent: Option<PomParent>,
    pub path: String,
    pub url: Option<String>,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PomParent {
    #[serde(rename = "artifactId")]
    pub artifact_id: String,
    #[serde(rename = "groupId")]
    pub group_id: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PomProperties {
    #[serde(rename = "artifactId")]
    pub artifact_id: String,
    #[serde(rename = "extraFields")]
    pub extra_fields: HashMap<String, String>,
    #[serde(rename = "groupId")]
    pub group_id: String,
    pub name: String,
    pub path: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Descriptor {
    pub configuration: Option<ConfigurationUnion>,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxRelease {
    #[serde(rename = "bugReportURL")]
    pub bug_report_url: Option<String>,
    #[serde(rename = "cpeName")]
    pub cpe_name: Option<String>,
    #[serde(rename = "homeURL")]
    pub home_url: Option<String>,
    pub id: Option<String>,
    #[serde(rename = "idLike")]
    pub id_like: Option<Vec<String>>,
    pub name: Option<String>,
    #[serde(rename = "prettyName")]
    pub pretty_name: Option<String>,
    #[serde(rename = "privacyPolicyURL")]
    pub privacy_policy_url: Option<String>,
    #[serde(rename = "supportURL")]
    pub support_url: Option<String>,
    pub variant: Option<String>,
    #[serde(rename = "variantID")]
    pub variant_id: Option<String>,
    pub version: Option<String>,
    #[serde(rename = "versionID")]
    pub version_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct File {
    pub classifications: Option<Vec<Classification>>,
    pub contents: Option<String>,
    pub digests: Option<Vec<Digest>>,
    pub id: String,
    pub location: Coordinates,
    pub metadata: Option<FileMetadataEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Classification {
    pub class: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileMetadataEntry {
    #[serde(rename = "groupID")]
    pub group_id: i64,
    #[serde(rename = "linkDestination")]
    pub link_destination: Option<String>,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    pub mode: i64,
    #[serde(rename = "type")]
    pub file_metadata_entry_type: String,
    #[serde(rename = "userID")]
    pub user_id: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Schema {
    pub url: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Secrets {
    pub location: Coordinates,
    pub secrets: Vec<SearchResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchResult {
    pub classification: String,
    pub length: i64,
    #[serde(rename = "lineNumber")]
    pub line_number: i64,
    #[serde(rename = "lineOffset")]
    pub line_offset: i64,
    #[serde(rename = "seekPosition")]
    pub seek_position: i64,
    pub value: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Source {
    pub target: Option<ConfigurationUnion>,
    #[serde(rename = "type")]
    pub source_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConfigurationUnion {
    AnythingArray(Vec<Option<serde_json::Value>>),
    AnythingMap(HashMap<String, Option<serde_json::Value>>),
    Bool(bool),
    Double(f64),
    Integer(i64),
    String(String),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Author {
    PhpComposerAuthors(PhpComposerAuthors),
    String(String),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FileUnion {
    FileRecord(FileRecord),
    String(String),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Size {
    Integer(i64),
    String(String),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum License {
    String(String),
    StringArray(Vec<String>),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SourceUnion {
    PhpComposerExternalReference(PhpComposerExternalReference),
    String(String),
}
