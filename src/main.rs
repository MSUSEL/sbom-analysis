extern crate futures;
#[macro_use]
extern crate serde;
extern crate tokio;

use std::collections::linked_list::LinkedList;
use std::io::stdout;
use std::io::Write;
use std::sync::Arc;

use dotenv::dotenv;
use futures::lock::Mutex;

use crate::api::vt::VtApi;
use crate::cli::{Cli, Commands};
use crate::context::ContextRunner;
use crate::format::{Error, read_file};
use crate::format::grype::Grype;
use crate::format::syft::Syft;
use crate::format::trivy::TrivyJson;

mod longest_zip;
mod format;
mod cvss;
mod api;
mod context;
#[cfg(test)]
mod test;
mod cli;

fn analyze(grype: &Option<String>, syft: &Option<String>, trivy: &Option<String>) -> Result<(), Error> {
    println!("Grype: {grype:?}");
    println!("Syft : {syft:?}");
    println!("Trivy: {trivy:?}");
    let grype: Option<Grype> =
        grype.as_ref().map(|path| read_file(&path)).transpose()?;
    let syft: Option<Syft> =
        syft.as_ref().map(|path| read_file(&path)).transpose()?;
    let trivy: Option<TrivyJson> =
        trivy.as_ref().map(|path| read_file(&path)).transpose()?;
    let _runner = ContextRunner::new()
        .grype(&grype).syft(&syft).trivy(&trivy);
    todo!("Read deployment context")
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    let cli = <Cli as clap::Parser>::parse();

    match &cli.subcommand {
        Commands::Analyze { grype, syft, trivy } =>
            analyze(grype, syft, trivy),
    }.expect("Failed to analyze");
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

