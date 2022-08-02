//! A vulnerability analysis tool designed to score vulnerabilities inside of a vulnerability report.

//! A vulnerability & sbom format analysis library.
//! This library is used to analyze software based on their vulnerabilities
//!
//! # Examples
//! ```
//! // Requires the 'grype' & 'trivy' features to be enabled
//! use std::collections::BTreeMap;
//! use scayl::{ContextRunner, DeploymentContext, Grype, read_json, Trivy, VulnerabilityFormat};
//! let grype: Grype = read_json("grype.json").unwrap();
//! let trivy: Trivy = read_json("trivy.json").unwrap();
//!
//! let scores: BTreeMap<_, _> = grype.cvss_v3_1_scores();
//! for (vuln_id, v3_metric) in scores {
//!     println!("{} {}", vuln_id, v3_metric);
//! }
//!
//! let context = DeploymentContext {
//!     ..Default::default()
//! };
//! // or
//! let context: DeploymentContext = read_json("context.json").unwrap();
//!
//! let mut runner = ContextRunner::new();
//! runner.grype(&grype);
//! runner.trivy(&trivy);
//! let score = runner.calculate(&context).unwrap();
//! println!("{:?}", score);
//! ```
//!
//! ```
//! // Requires the 'cyclonedx' feature to be enabled
//! use scayl::{ContextRunner, CycloneDx, DeploymentContext, read_json};
//! let cyclone: CycloneDx = read_json("cyclonedx.json").unwrap();
//! let context: DeploymentContext = read_json("context.json").unwrap();
//!
//! let mut runner = ContextRunner::new();
//!  runner.cyclonedx(&cyclone);
//! let score = runner.calculate(&context).unwrap();
//! println!("{:?}", score);
//! ```

extern crate futures;
#[macro_use]
extern crate serde;
extern crate tokio;

#[cfg(test)]
mod test;

/// This module contains the different SBOM and Vulnerability Report formats.
pub mod format;

/// This module contains CVSS v2.0 & CVSS v3.0 scoring systems and data models
pub mod cvss;

/// This model contains some apis for vulnerability related services (incomplete)
pub mod api;

/// The main module containing the scoring mechanism & deployment contexts
pub mod context;

/// Contains some traits for generic vulnerability & cvss functionality
pub mod model;

/// This module contains some useful tools for reading/writing files
pub mod util;

pub use format::*;
pub use cvss::*;
pub use api::*;
pub use context::*;
pub use model::*;
pub use util::*;

#[cfg(feature = "syft")]
#[allow(unused)]
/// Retrieves file reports from the VT API and prints them to stdout.
async fn get_file_reports(syft: &crate::Syft) {
    use std::collections::LinkedList;
    use std::io::{Write, stdout};
    use std::sync::Arc;
    use futures::lock::Mutex;
    use crate::format::VulnerabilityFormat;
    use crate::cvss::v3_1;
    use crate::model::Cvss;

    use crate::api::vt::VtApi;

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

