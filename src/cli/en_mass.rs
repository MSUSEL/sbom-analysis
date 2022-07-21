use std::collections::{BTreeMap, LinkedList};
use std::fs;
use std::fs::File;
use std::io::{BufWriter, stdout};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use futures::lock::Mutex;

use scayl::{DeploymentContext, Grype, read_json, RecurseDir, Trivy, VulnerabilityFormat, VulnerabilityScore, VulnFilter, VulnFormat};

pub async fn en_mass<P, CP>(path: P, context: CP)
    where P: AsRef<Path>,
          CP: AsRef<Path> {
    let files: LinkedList<_> = VulnFilter.recurse_dir(
        path.as_ref().to_path_buf(),
        |path, fmt| (path, fmt),
    );

    // TODO: Throw an actual error if the context file doesn't exist.
    let context: DeploymentContext = read_json(context.as_ref()).unwrap();

    let num_threads = num_cpus::get().min(files.len());
    let files = Arc::new(Mutex::new(files));
    let handles = (0..num_threads).map(|_| {
        let files = files.clone();
        let context = context.clone();
        tokio::spawn(async move {
            let mut out = LinkedList::new();
            while let Some((path, fmt)) = files.lock().await.pop_front() {
                let name = path.to_string_lossy().to_string()
                    .replace("\\", "_")[2..]
                    .to_string();
                let folder = path.parent().unwrap().to_string_lossy().to_string()
                    .replace("\\", "_")[2..]
                    .to_string();
                let begin = path.display().to_string();
                let end = begin.clone();
                let vulns = match fmt {
                    VulnFormat::Grype => {
                        tokio::spawn(async move {
                            let mut lock = stdout().lock();
                            writeln!(lock, "Reading file: {}", begin).unwrap();
                        });
                        let grype: Grype = read_json(&path)
                            .expect(format!("Failed to read file: {}", path.display()).as_str());
                        tokio::spawn(async move {
                            let mut lock = stdout().lock();
                            writeln!(lock, "Done reading file: {}", end).unwrap();
                        });
                        grype.cvss_v3_1_scores()
                    }
                    VulnFormat::Trivy => {
                        tokio::spawn(async move {
                            let mut lock = stdout().lock();
                            writeln!(lock, "Reading file: {}", begin).unwrap();
                        });
                        let trivy: Trivy = read_json(&path)
                            .expect(format!("Failed to read file: {}", path.display()).as_str());
                        tokio::spawn(async move {
                            let mut lock = stdout().lock();
                            writeln!(lock, "Done reading file: {}", end).unwrap();
                        });
                        trivy.cvss_v3_1_scores()
                    }
                };

                out.push_back((name, folder, vulns));
            }


            out.into_iter().map(|(name, folder, vulns)| {
                let scores =
                    vulns.into_iter().map(|(id, metric)| {
                        (id, context.score_v3(&metric))
                    }).collect::<BTreeMap<_, _>>();

                (
                    (name, scores.clone()),
                    (folder, scores.clone()),
                )
            }).collect::<Vec<_>>()
        })
    }).collect::<Vec<_>>();

    let mut files = BTreeMap::new();
    let mut folders = BTreeMap::new();
    for handle in handles {
        let out = handle.await.unwrap();
        for (file, folder) in out {
            files.insert(file.0, file.1);
            folders.entry(folder.0)
                .or_insert_with(|| BTreeMap::new())
                .extend(folder.1);
        }
    }

    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let uri = format!("./en-mass/{}", now);
    fs::create_dir_all(uri.clone()).unwrap();
    for (name, cves) in files {
        if cves.is_empty() {
            continue;
        }
        let uri = format!("{}/{}.csv", uri.clone(), name);
        let mut writer = BufWriter::new(File::create(uri).unwrap());
        write!(writer, "id,sum,network,remote,sensitivity,clperms,fsperms").unwrap();
        for (id, VulnerabilityScore {
            sum, network, files, remote, information, permissions
        }) in cves {
            write!(writer, "\n{},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2}",
                   id, sum, network, information, remote, permissions, files
            ).unwrap();
        }
    }

    for (name, cves) in folders {
        if cves.is_empty() {
            continue;
        }
        let uri = format!("{}/{}.csv", uri.clone(), name);
        let mut writer = BufWriter::new(File::create(uri).unwrap());
        write!(writer, "id,sum,network,remote,sensitivity,clperms,fsperms").unwrap();
        for (id, VulnerabilityScore {
            sum, network, files, remote, information, permissions
        }) in cves {
            write!(writer, "\n{},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2}",
                   id, sum, network, information, remote, permissions, files
            ).unwrap();
        }
    }

    println!("Finished writing to {}!", uri);
}