use std::collections::LinkedList;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::sync::Arc;

use futures::lock::Mutex;

use crate::{context, ContextRunner, Grype, Syft, Trivy};
use crate::context::{DeploymentContext, DeploymentScore, VulnerabilityScore};
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
            }
        }
    }
}

pub async fn analyze(
    grype: &Vec<String>,
    syft: &Vec<String>,
    trivy: &Vec<String>,
    context: &String,
    out: &Option<String>,
) -> Result<DeploymentScore, Error> {
    let out = out.as_ref().map(|v| File::create(v).unwrap());
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

    let res = runner.calculate(&context);

    let score = res.map_err(Error::Context)?;

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
    let mut lengths = header.iter().map(|v| v.len() + 2).collect::<Vec<_>>();
    let mut columns = LinkedList::from([
        header
    ]);

    for (idx, (id, VulnerabilityScore {
        sum, network, files, remote, information, permissions
    })) in score.scores.iter().enumerate() {
        let column = [
            format!("{}", idx),
            format!("{}", id),
            format!("{:.2}", sum),
            format!("{:.2}", network),
            format!("{:.2}", files),
            format!("{:.2}", remote),
            format!("{:.2}", information),
            format!("{:.2}", permissions),
        ];
        for (i, v) in column.iter().enumerate() {
            lengths[i] = v.len().max(lengths[i]);
        }
        columns.push_back(column);
    }

    if score.scores.is_empty() {
        println!("No vulnerabilities found (0.0/5.0)");
        return Ok(score);
    }

    if let Some(out) = out {
        use std::io::Write;
        let mut writer = BufWriter::new(out);
        write!(writer, "id,sum,network,files,remote,information,permissions").unwrap();
        for (id, VulnerabilityScore {
            sum, network, files, remote, information, permissions
        }) in &score.scores {
            write!(writer, "\n{},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2}",
                   id, sum, network, files, remote, information, permissions).unwrap();
        }
    } else {
        print!("┌");
        for (i, len) in lengths.iter().enumerate() {
            if i > 0 {
                print!("┬");
            }
            print!("{:─<1$}", "─", len + 2);
        }
        println!("┐");

        for (i, column) in columns.iter().enumerate() {
            if i > 0 {
                print!("├");
                for (i, len) in lengths.iter().enumerate() {
                    if i > 0 {
                        print!("┼");
                    }
                    print!("{:─<1$}", "─", len + 2);
                }
                println!("┤");
            }

            print!("│");
            for (i, row) in column.iter().enumerate() {
                if i > 0 {
                    print!("│");
                }
                print!(" {:<1$}", row, lengths[i] + 1);
            }
            println!("│");
        }
        print!("└");
        for (i, len) in lengths.iter().enumerate() {
            if i > 0 {
                print!("┴");
            }
            print!("{:─<1$}", "─", len + 2);
        }
        println!("┘");
        println!();
    }

    Ok(score)
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