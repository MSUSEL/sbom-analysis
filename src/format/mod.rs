#![allow(dead_code)]

use std::fmt::{Display, Formatter};
use std::path::Path;
use serde::de::DeserializeOwned;

pub mod sarif;
pub mod syft;
pub mod nvd_cve;
pub mod trivy;
pub mod grype;

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