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

pub mod format;
pub mod cvss;
pub mod api;
pub mod context;
pub mod model;
pub mod util;

pub use format::*;
pub use cvss::*;
pub use api::*;
pub use context::*;
pub use model::*;
pub use util::*;