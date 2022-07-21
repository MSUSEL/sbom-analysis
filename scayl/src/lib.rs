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

