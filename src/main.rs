mod longest_zip;
mod format;
mod cvss;
mod api;
mod context;
#[cfg(test)]
mod test;

#[macro_use]
extern crate serde;
extern crate tokio;
extern crate futures;

use std::collections::linked_list::LinkedList;
use std::io::Write;
use std::io::{stdout};
use std::sync::Arc;
use dotenv::dotenv;
use futures::lock::Mutex;
use crate::api::vt::VtApi;
use crate::context::{ContextRunner, DeploymentContext, FileSystemAccess, InformationSensitivity, NetworkConfiguration, Permissions, RemoteAccess};
use crate::format::grype::Grype;
use crate::format::read_file;
use crate::format::syft::Syft;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let grype: Grype = read_file("cache/molkars/pbd/1.0/grype.json").unwrap();
    let analyzer = ContextRunner::new()
        .grype(&grype);
    let ctx = DeploymentContext {
        file_system_access: FileSystemAccess::Required,
        information_sensitivity: InformationSensitivity::Insensitive,
        permissions: Permissions::Restricted,
        remote_access: RemoteAccess::None,
        network_connection: NetworkConfiguration::Public
    };
    analyzer.calculate(&ctx);
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

