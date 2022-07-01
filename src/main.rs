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
use crate::format::syft::Syft;

#[tokio::main]
async fn main() {
    dotenv().ok();
    // get_file_reports(&syft).await;
}

#[cfg(test)]
mod tests {
    use std::collections::LinkedList;
    use std::path::PathBuf;
    use crate::format::grype::Grype;
    use std::fs;
    use crate::format::read_file;

    #[tokio::test]
    async fn test_grype() {

        let mut queue = LinkedList::new();
        queue.push_back(PathBuf::from("cache"));
        while let Some(next) = queue.pop_front() {
            if !next.is_dir() {
                if next.file_name().unwrap().to_string_lossy().to_string() == "grype.json" {
                    println!("Reading Grype: {}", next.display());
                    let _: Grype = read_file(next).unwrap();
                }
            } else {
                for entry in fs::read_dir(next).unwrap() {
                    let entry = entry.unwrap();
                    let path = entry.path();
                    queue.push_back(path);
                }
            }
        }
    }
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

