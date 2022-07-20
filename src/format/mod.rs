#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};
use serde::de::DeserializeOwned;
use crate::util::io::RecurseDir;
use crate::v3_1::BaseMetric;

pub mod sarif;
pub mod syft;
pub mod nvd_cve;
pub mod trivy;
pub mod grype;

pub use grype::Grype;
pub use syft::Syft;
pub use trivy::Trivy;

pub struct GrypeFileFilter;

pub struct TrivyFileFilter;

impl RecurseDir<()> for GrypeFileFilter {
    fn matches(&self, path: &PathBuf) -> Option<()> {
        path.file_name()
            .map(|v| v.to_string_lossy().to_string())
            .filter(|v| v == "grype.json")
            .map(|_| ())
    }
}

impl RecurseDir<()> for TrivyFileFilter {
    fn matches(&self, path: &PathBuf) -> Option<()> {
        path.file_name()
            .map(|v| v.to_string_lossy().to_string())
            .filter(|v| v == "trivy.json")
            .map(|_| ())
    }
}

#[derive(Debug, Clone)]
pub enum VulnFormat {
    Grype,
    Trivy,
}

pub struct VulnFilter;

impl RecurseDir<VulnFormat> for VulnFilter {
    fn matches(&self, path: &PathBuf) -> Option<VulnFormat> {
        GrypeFileFilter.matches(path)
            .map(|_| VulnFormat::Grype)
            .or_else(||
                TrivyFileFilter.matches(path)
                    .map(|_| VulnFormat::Trivy))
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct VulnId {
    pub namespace: String,
    pub year: u32,
    pub id: String,
    pub tag: Option<String>,
}

impl Display for VulnId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}-{}", self.namespace, self.year, self.id)?;
        if let Some(tag) = &self.tag {
            write!(f, "{}", tag)?;
        }
        Ok(())
    }
}

impl TryFrom<String> for VulnId {
    type Error = ();

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut iter = value.split('-');
        let namespace = iter.next().ok_or(())?;
        let year = iter.next().ok_or(())?
            .parse::<u32>()
            .map_err(|_| ())?;
        let id = iter.next().ok_or(())?;
        let tag = iter.collect::<String>();
        let tag = if tag.is_empty() { None } else { Some(tag) };

        Ok(Self {
            namespace: namespace.to_string(),
            year,
            id: id.to_string(),
            tag,
        })
    }
}

pub trait VulnerabilityFormat {
    fn cvss_v3_1_scores(&self) -> BTreeMap<VulnId, BaseMetric>;
}

impl<T: VulnerabilityFormat> VulnerabilityFormat for &T {
    fn cvss_v3_1_scores(&self) -> BTreeMap<VulnId, BaseMetric> {
        (*self).cvss_v3_1_scores()
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Serde(serde_json::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "IO error: {}", e),
            Error::Serde(e) => write!(f, "Serde error: {}", e),
        }
    }
}

pub fn read_file<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<T, Error> {
    let file = std::fs::File::open(path).map_err(Error::Io)?;
    let reader = std::io::BufReader::new(file);
    serde_json::from_reader(reader).map_err(Error::Serde)
}