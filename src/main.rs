extern crate futures;
#[macro_use]
extern crate serde;
extern crate tokio;

use std::collections::linked_list::LinkedList;
use std::io::stdout;
use std::io::Write;
use std::sync::Arc;

use clap::Parser;
use dotenv::dotenv;
use futures::lock::Mutex;

use crate::api::vt::VtApi;
use crate::cli::{Cli, Commands};
use crate::cli::analyze::analyze;
use crate::context::ContextRunner;
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

#[tokio::main]
async fn main() {
    dotenv().ok();

    let cli: Cli = Parser::parse();

    match &cli.subcommand {
        Commands::Analyze { grype, syft, trivy, context, weights } =>
            analyze(grype, syft, trivy, context, weights),
    }
        .await
        .expect("Failed to analyze");
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

