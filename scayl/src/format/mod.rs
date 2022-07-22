#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};

use serde::de::{DeserializeOwned, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "grype")]
pub use grype::*;
#[cfg(feature = "nvd")]
pub use nvd::*;
#[cfg(feature = "sarif")]
pub use sarif::*;
#[cfg(feature = "syft")]
pub use syft::*;
#[cfg(feature = "trivy")]
pub use trivy::*;
#[cfg(feature = "cyclonedx")]
pub use cyclonedx::*;

use crate::v3_1::BaseMetric;

#[cfg(feature = "sarif")]
pub mod sarif;
#[cfg(feature = "syft")]
pub mod syft;
#[cfg(feature = "nvd")]
pub mod nvd;
#[cfg(feature = "trivy")]
pub mod trivy;
#[cfg(feature = "grype")]
pub mod grype;
#[cfg(feature = "cyclonedx")]
pub mod cyclonedx;

#[derive(Debug, Clone)]
pub enum VulnFormat {
    Grype,
    Trivy,
}

pub struct VulnFilter;

impl crate::RecurseDir<VulnFormat> for VulnFilter {
    fn matches(&self,
               #[cfg(any(feature = "grype", feature = "trivy"))]
               path: &PathBuf,
               #[cfg(not(any(feature = "grype", feature = "trivy")))]
               _path: &PathBuf,
    ) -> Option<VulnFormat> {
        #[cfg(feature = "grype")]
        if let Some(_) = GrypeFileFilter.matches(path) {
            return Some(VulnFormat::Grype);
        }

        #[cfg(feature = "trivy")]
        if let Some(_) = TrivyFileFilter.matches(path) {
            return Some(VulnFormat::Trivy);
        }

        None
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct VulnId {
    pub namespace: String,
    pub year: u32,
    pub id: String,
    pub tag: Option<String>,
}

impl Serialize for VulnId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for VulnId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        deserializer.deserialize_str(VulnIdVisitor)
    }
}

struct VulnIdVisitor;

impl<'de> Visitor<'de> for VulnIdVisitor {
    type Value = VulnId;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("A vulnerability-id string: `<namespace>-<year>-<id>[-tag]")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where E: serde::de::Error {
        let mut parts = v.split('-');
        let namespace = parts.next().ok_or_else(|| serde::de::Error::custom("missing namespace"))?;
        let year = parts.next().ok_or_else(|| serde::de::Error::custom("missing year"))?;
        let id = parts.next().ok_or_else(|| serde::de::Error::custom("missing id"))?;
        let tag = parts.next().map(|s| s.to_string());
        Ok(VulnId {
            namespace: namespace.to_string(),
            year: year.parse().map_err(|_| serde::de::Error::custom("invalid year"))?,
            id: id.to_string(),
            tag,
        })
    }
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

pub fn read_json<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<T, Error> {
    let file = std::fs::File::open(path).map_err(Error::Io)?;
    let reader = std::io::BufReader::new(file);
    serde_json::from_reader(reader).map_err(Error::Serde)
}