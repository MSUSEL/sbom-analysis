#![allow(dead_code)]

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

pub fn read_file<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<T, Error> {
    println!("Reading file: {:?}", path.as_ref());
    let file = std::fs::File::open(path).map_err(Error::Io)?;
    let reader = std::io::BufReader::new(file);
    serde_json::from_reader(reader).map_err(Error::Serde)
}