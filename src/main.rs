mod longest_zip;
mod format;
mod cvss;
mod api;

#[macro_use]
extern crate serde;
extern crate futures;

use std::io::Write;
use std::any::Any;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, BTreeMap, BTreeSet, HashMap, HashSet, LinkedList};
use std::collections::hash_map::RandomState;
use std::f32;
use std::fs::File;
use std::io::{BufReader, stdout};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use dotenv::dotenv;
use reqwest::Error;
use serde_json::Value;
use futures::lock::Mutex;
use crate::api::vt::VtApi;
use crate::format::sarif::Sarif;
use crate::format::syft::Syft;

type Res<T, E> = std::result::Result<T, E>;

fn read_sarif(path: impl AsRef<Path>) -> Res<Sarif, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).map_err(|e| e.to_string())
}

fn read_syft(path: impl AsRef<Path>) -> Res<Syft, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).map_err(|e| e.to_string())
}

extern crate tokio;

#[tokio::main]
async fn main() {
    dotenv().ok();
    let mut syft = read_syft("pbd.syft.sbom.json").unwrap();
    get_file_reports(&syft).await;
}

async fn get_file_reports(syft: &Syft) {
    let futures = syft.artifacts
        .iter()
        .filter_map(|v| v.metadata.as_ref()
            .and_then(|v| v.digest.as_ref()))
        .flat_map(|f| f.iter())
        .map(|digest| digest.value.clone())
        .enumerate()
        .collect::<LinkedList<_>>();
    println!("N: {}", futures.len());
    let futures = Arc::new(Mutex::new(futures));

    let handles = (0..4).map(|_| {
        let futures = futures.clone();
        tokio::spawn(async move {
            let vtAPI = VtApi::new(reqwest::Client::new());
            let futures = futures;

            while let Some((idx, hash)) = futures.lock().await.pop_front() {
                writeln!(stdout().lock(), "{:4} -> {:?}", idx, hash).ok();
                let future = vtAPI.fileReport(hash)
                    .await;
                writeln!(stdout().lock(), "{:?}", future).ok();
            }
        })
    }).collect::<Vec<_>>();
    for handle in handles {
        handle.await.expect("AY")
    }
}

