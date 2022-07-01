mod longest_zip;
mod format;
mod cvss;
mod api;
mod context;

#[macro_use]
extern crate serde;
extern crate tokio;
extern crate futures;

use std::io::Write;
use std::collections::LinkedList;
use std::io::{stdout};
use std::sync::Arc;
use dotenv::dotenv;
use futures::lock::Mutex;
use crate::api::vt::VtApi;
use crate::format::grype::Grype;
use crate::format::read_file;
use crate::format::syft::Syft;

#[tokio::main]
async fn main() {
    dotenv().ok();
    let _: Grype = read_file("cache/itzg/minecraft-server/java8/grype.json").unwrap();
    let _: Grype = read_file("cache/itzg/minecraft-server/java11/grype.json").unwrap();
    let _: Grype = read_file("cache/itzg/minecraft-server/java17/grype.json").unwrap();
    let _: Grype = read_file("cache/molkars/pbd/1.0/grype.json").unwrap();
    let _: Grype = read_file("cache/alpine/latest/grype.json").unwrap();
    let _: Grype = read_file("cache/nginx/latest/grype.json").unwrap();
    let _: Grype = read_file("cache/ubuntu/latest/grype.json").unwrap();
    // get_file_reports(&syft).await;
}

#[allow(dead_code)]
async fn get_file_reports(syft: &Syft) {
    let digests = syft.get_file_digests::<LinkedList<_>>()
        .into_iter()
        .enumerate();
    let futures = Arc::new(Mutex::new(digests));

    let handles = (0..4).map(|_| {
        let futures = futures.clone();
        tokio::spawn(async move {
            let vt_api = VtApi::new(reqwest::Client::new());
            let futures = futures;

            while let Some((idx, hash)) = futures.lock().await.next() {
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

