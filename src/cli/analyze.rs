use std::collections::LinkedList;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use futures::lock::Mutex;

use crate::{context, ContextRunner, Grype, Syft, Trivy};
use crate::context::{DeploymentContext, DeploymentScore};
use crate::format;

enum Fmt {
    Grype,
    Trivy,
    Syft,
}

struct InFile {
    uri: String,
    format: Fmt,
}

enum OutFile {
    Grype(Grype),
    Syft(Syft),
    Trivy(Trivy),
}

#[derive(Debug)]
pub enum Error {
    Format(format::Error),
    Context(LinkedList<context::Error>),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Format(err) => write!(f, "{}", err),
            Error::Context(err) => {
                writeln!(f, "Context errors:")?;
                for err in err {
                    writeln!(f, "  {}", err)?;
                }
                Ok(())
            },
        }
    }
}

pub async fn analyze(
    grype: &Vec<String>,
    syft: &Vec<String>,
    trivy: &Vec<String>,
    context: &String,
) -> Result<DeploymentScore, Error> {
    let context: DeploymentContext = format::read_file(context).map_err(Error::Format)?;

    let mut files = LinkedList::new();

    files.extend(grype.iter().map(|v| InFile { uri: v.clone(), format: Fmt::Grype }));
    files.extend(syft.iter().map(|v| InFile { uri: v.clone(), format: Fmt::Syft }));
    files.extend(trivy.iter().map(|v| InFile { uri: v.clone(), format: Fmt::Trivy }));

    let num_cpus = (2 * num_cpus::get()).min(files.len());
    let files = Arc::new(Mutex::new(files));
    let handles = (0..num_cpus).map(|_| {
        let files = files.clone();
        tokio::task::spawn(async move {
            let mut out = LinkedList::new();
            while let Some(file) = files.lock().await.pop_front() {
                out.push_back(read_file(file));
            }
            out
        })
    }).collect::<Vec<_>>();

    let mut files = LinkedList::new();
    let mut runner = ContextRunner::new();
    for handle in handles {
        let res = handle.await.expect("Failed to analyze");
        let res = res.into_iter()
            .collect::<Result<LinkedList<OutFile>, _>>().map_err(Error::Format)?;
        files.extend(res);
    }

    for file in &files {
        match file {
            OutFile::Grype(v) => runner.grype(v),
            OutFile::Syft(v) => runner.syft(v),
            OutFile::Trivy(v) => runner.trivy(v),
        };
    }

    let res = runner.calculate(&context,);

    res.map_err(Error::Context)
}

fn read_file(InFile { uri, format }: InFile) -> Result<OutFile, format::Error> {
    let file = File::open(&uri).map_err(format::Error::Io)?;
    let reader = BufReader::new(file);

    let out = match format {
        Fmt::Grype => {
            let res: Grype = serde_json::from_reader(reader)
                .map_err(format::Error::Serde)?;
            OutFile::Grype(res)
        }
        Fmt::Trivy => {
            let res: Trivy =
                serde_json::from_reader(reader)
                    .map_err(format::Error::Serde)?;
            OutFile::Trivy(res)
        }
        Fmt::Syft => {
            let res: Syft = serde_json::from_reader(reader)
                .map_err(format::Error::Serde)?;
            OutFile::Syft(res)
        }
    };

    Ok(out)
}