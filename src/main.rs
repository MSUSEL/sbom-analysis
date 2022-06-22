mod longest_zip;
mod format;
mod cvss;
mod api;

#[macro_use]
extern crate serde;

use std::any::Any;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, BTreeMap, BTreeSet, HashMap, HashSet};
use std::collections::hash_map::RandomState;
use std::f32;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::str::FromStr;
use serde_json::Value;
use crate::format::sarif::Sarif;

type Res<T, E> = std::result::Result<T, E>;

fn read_sarif(path: impl AsRef<Path>) -> Res<Sarif, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).map_err(|e| e.to_string())
}

fn main() {
    let mut trivy: Sarif = read_sarif("grype.sarif.json").unwrap();

    let avg = trivy.average_cvss_score();
    let median = trivy.median_cvss_score();

    println!("Median Average: {} {:.2}", median, avg);
}

