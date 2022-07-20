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
use crate::cli::{analyze::analyze, en_mass::en_mass};
use crate::context::ContextRunner;
use crate::cvss::v3_1;
use crate::format::VulnerabilityFormat;
use crate::format::{Grype, Syft, Trivy};
use crate::model::Cvss;

mod format;
mod cvss;
mod api;
mod context;
#[cfg(test)]
mod test;
mod cli;
mod model;

mod util;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let cli: Cli = Parser::parse();

    match &cli.subcommand {
        Commands::Analyze { grype, syft, trivy, context, file } => {
            analyze(grype, syft, trivy, context, file)
                .await
                .expect("Failed to analyze");
        }
        Commands::EnMass { path, context } => {
            en_mass(path, context).await;
        }
    }
}

#[allow(dead_code)]
/// Retrieves file reports from the VT API and prints them to stdout.
async fn get_file_reports(syft: &Syft) {
    let digests = syft.get_file_digests::<LinkedList<_>>()
        .into_iter()
        .enumerate();

    // Arc<Mutex<_>> allows us to share the same value across different threads
    // Arc lets us move the value around without copying
    // Mutex lets us modify the value safely across threads
    let futures = Arc::new(Mutex::new(digests));

    let _handles = (0..4).map(|_| {
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
}

