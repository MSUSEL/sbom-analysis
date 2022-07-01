mod longest_zip;
mod format;
mod cvss;
mod api;
mod context;

#[macro_use]
extern crate serde;
extern crate futures;

use std::io::Write;
use std::collections::LinkedList;
use std::fs::File;
use std::io::{BufReader, stdout};
use std::path::Path;
use std::sync::Arc;
use dotenv::dotenv;
use futures::lock::Mutex;
use crate::api::vt::VtApi;
use crate::format::sarif::Sarif;
use crate::format::syft::Syft;

type Res<T, E> = Result<T, E>;

#[allow(dead_code)]
fn read_sarif(path: impl AsRef<Path>) -> Res<Sarif, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).map_err(|e| e.to_string())
}

#[allow(dead_code)]
fn read_syft(path: impl AsRef<Path>) -> Res<Syft, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).map_err(|e| e.to_string())
}

extern crate tokio;

#[tokio::main]
async fn main() {
    dotenv().ok();
    let syft = read_syft("pbd.syft.sbom.json").unwrap();
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
            let vt_api = VtApi::new(reqwest::Client::new());
            let futures = futures;

            while let Some((idx, hash)) = futures.lock().await.pop_front() {
                writeln!(stdout().lock(), "{:4} -> {:?}", idx, hash).ok();
                let future = vt_api.file_report(hash)
                    .await;
                writeln!(stdout().lock(), "{:?}", future).ok();
            }
        })
    }).collect::<Vec<_>>();
    for handle in handles {
        handle.await.expect("AY")
    }
}

