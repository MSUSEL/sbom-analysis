use std::cmp::Ordering;
use std::collections::LinkedList;
use std::ffi::OsStr;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{BufReader, BufWriter, stdout};
use std::path::Path;
use std::sync::Arc;

use futures::lock::Mutex;

use scayl::{context, ContextRunner, CycloneDx, Grype, Syft, Trivy, write_json, write_table};
use scayl::context::{DeploymentContext, DeploymentScore, VulnerabilityScore};
use scayl::format;

/// The vulnerability format of a file
enum Fmt {
    Grype,
    Trivy,
    Syft,
    CycloneDx,
}

/// An internal input file
struct InFile {
    uri: String,
    format: Fmt,
}

/// An internal output file
enum OutFile {
    Grype(Grype),
    Syft(Syft),
    CycloneDx(CycloneDx),
    Trivy(Trivy),
}

/// An error representing possible issues during the analysis process
#[derive(Debug)]
pub enum Error {
    /// An error that occurred while reading data from a vulnerability
    Format(format::Error),
    /// An error that occurred while organizing and scoring vulnerabilities
    Context(LinkedList<context::Error>),
    /// An error that occurred when reading a vulnerability/sbom file
    Io(std::io::Error),
    /// The file format of an input file is unsupported
    BadFileExtension(String),
    /// An error occurred while parsing a json file, usually a schema issue
    Serde(serde_json::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Format(err) => write!(f, "{}", err),
            Error::Context(err) => {
                writeln!(f, "Context Errors:")?;
                for err in err {
                    writeln!(f, "  {}", err)?;
                }
                Ok(())
            }
            Error::Io(err) => write!(f, "IO Error: {}", err),
            Error::BadFileExtension(ext) => write!(f, "Bad file extension: {}", ext),
            Error::Serde(err) => write!(f, "Serialization error: {}", err),
        }
    }
}

/// The main entry point for the analysis process
///
/// # Arguments
/// * `grype` - The grype files that describe a _single_ piece of software
/// * `trivy` - The trivy files that describe a _single_ piece of software
/// * `syft` - The syft files that describe a _single_ piece of software
/// * `cyclonedx` - The cyclonedx files that describe a _single_ piece of software. Often conflicts with `trivy`
/// * `context` - The context file that describes the deployment
/// * `out` - An optional output file to write the results to. If not specified, the results will be printed to stdout.
///
/// # Returns
/// A `Result` containing the `DeploymentScore` or an `Error` if an error occurred.
///
/// # Examples
/// ```
/// use scayl::analyze;
/// let score = analyze(
///     &vec!["/path/to/grype.json".to_string()],
///     &vec!["/path/to/trivy.json".to_string()],
///     &vec!["/path/to/syft.json".to_string()],
///     &vec![],
///     &Some("/path/to/context/file".to_string()),
///     &None
/// ).unwrap();
/// ```
pub async fn analyze(
    grype: &Vec<String>,
    syft: &Vec<String>,
    trivy: &Vec<String>,
    cyclone_dx: &Vec<String>,
    context: &String,
    out: &Option<String>,
) -> Result<DeploymentScore, Error> {
    let context: DeploymentContext = format::read_json(context).map_err(Error::Format)?;

    let mut files = LinkedList::new();

    // Add different files to the list of files to analyze
    files.extend(grype.iter().map(|v| InFile { uri: v.clone(), format: Fmt::Grype }));
    files.extend(syft.iter().map(|v| InFile { uri: v.clone(), format: Fmt::Syft }));
    files.extend(trivy.iter().map(|v| InFile { uri: v.clone(), format: Fmt::Trivy }));
    files.extend(cyclone_dx.iter().map(|v| InFile { uri: v.clone(), format: Fmt::CycloneDx }));

    // read each file on a different thread
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

    // Collect the read files and take out any errors
    let mut files = LinkedList::new();
    for handle in handles {
        let res = handle.await.expect("Failed to analyze");
        let res = res.into_iter()
            .collect::<Result<LinkedList<OutFile>, _>>().map_err(Error::Format)?;
        files.extend(res);
    }

    // Add the files to the runner
    let mut runner = ContextRunner::new();
    for file in &files {
        match file {
            OutFile::Grype(v) => runner.grype(v),
            OutFile::Syft(v) => runner.syft(v),
            OutFile::Trivy(v) => runner.trivy(v),
            OutFile::CycloneDx(v) => runner.cyclone_dx(v),
        };
    }

    let res = runner.calculate(&context);
    let score = res.map_err(Error::Context)?;

    let mut scores = score.scores.values().map(|v| {
        v.sum
    }).collect::<Vec<_>>();
    scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let mut iter = scores.iter();
    let lower = iter.position(|v| *v > 5.0 * 0.33).unwrap_or(scores.len());
    let upper = iter.position(|v| *v > 5.0 * 0.66).unwrap_or(scores.len());

    println!("{:.2}% of scores are below a 1.65 (5 / 3)", lower as f64 / scores.len() as f64 * 100.0);
    println!("{:.2}% of scores are below a 3.3 (5 * 2 / 3)", upper as f64 / scores.len() as f64 * 100.0);

    if score.scores.is_empty() {
        println!("No vulnerabilities found (0.0/5.0)");
        return Ok(score);
    }

    if let Some(file) = out {
        use std::io::Write;
        let (use_csv, file) = match Path::new(file).extension().and_then(OsStr::to_str) {
            None => (true, format!("{}.csv", file)),
            Some("json") => (false, file.clone()),
            Some("csv") => (true, file.clone()),
            Some(v) => return Err(Error::BadFileExtension(v.to_string())),
        };


        if use_csv {
            let file = File::create(file).map_err(Error::Io)?;
            let mut writer = BufWriter::new(file);
            write!(writer, "id,sum,network,files,remote,information,permissions").unwrap();
            for (id, VulnerabilityScore {
                sum, network, files, remote, information, permissions
            }) in &score.scores {
                write!(writer, "\n{},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4}",
                       id, sum, network, files, remote, information, permissions).unwrap();
            }
        } else {
            write_json(&file, &score)
                .map_err(|e| match e {
                    format::Error::Io(e) => Error::Io(e),
                    format::Error::Serde(e) => Error::Serde(e),
                })?;
        }
        return Ok(score);
    }
    let header = [
        "".to_string(),
        "id".to_string(),
        "sum".to_string(),
        "network".to_string(),
        "files".to_string(),
        "remote".to_string(),
        "information".to_string(),
        "permissions".to_string(),
    ];


    let mut values = LinkedList::new();
    for (idx, (id, score)) in score.scores.iter().enumerate() {
        values.push_back([
            format!("{}", idx),
            format!("{}", id),
            format!("{:.4}", score.sum),
            format!("{:.4}", score.network),
            format!("{:.4}", score.files),
            format!("{:.4}", score.remote),
            format!("{:.4}", score.information),
            format!("{:.4}", score.permissions),
        ]);
    }

    write_table(&mut stdout(), header, values)
        .map_err(Error::Io)?;

    Ok(score)
}

/// Read a file and return the contents as an `OutFile`
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
        Fmt::CycloneDx => {
            let res: CycloneDx = serde_json::from_reader(reader)
                .map_err(format::Error::Serde)?;
            OutFile::CycloneDx(res)
        }
    };

    Ok(out)
}