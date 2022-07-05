use std::collections::linked_list::LinkedList;
use std::path::{Path, PathBuf};
use crate::format::grype::Grype;
use crate::format::read_file;
use crate::Syft;

trait RecurseDir {
    fn file(&self, path: PathBuf) -> ();
}

fn recurse_dir<T: RecurseDir>(path: PathBuf, visitor: T) {
    let mut queue = LinkedList::new();
    queue.push_back(path);

    while let Some(next) = queue.pop_front() {
        if next.is_dir() {
            let entry = next.read_dir().unwrap();
            for e in entry {
                let e = e.unwrap();
                if e.path().is_dir() {
                    queue.push_back(e.path());
                } else {
                    visitor.file(e.path());
                }
            }
        } else {
            visitor.file(next);
        }
    }
}

struct GrypeVisitor;

impl RecurseDir for GrypeVisitor {
    fn file(&self, path: PathBuf) -> () {
        if path.file_name().unwrap().to_string_lossy().to_string() != "grype.json" {
            return;
        }
        println!("Reading Grype: {}", path.display());
        let res: Result<Grype, _> = read_file(path);
        if let Err(ref e) = res {
            println!("Error: {}", e);
        }
        assert!(res.is_ok());
    }
}

#[test]
fn test_grype() {
    let path = Path::new("cache");
    recurse_dir(path.to_path_buf(), GrypeVisitor);
}

struct SyftVisitor;

impl RecurseDir for SyftVisitor {
    fn file(&self, path: PathBuf) -> () {
        let file_name = path.file_name().unwrap().to_string_lossy().to_string();
        if file_name != "syft.sbom.json" {
            return;
        }
        let res: Result<Syft, _> = read_file(path);
        if let Err(ref e) = res {
            println!("Error: {}", e);
        }
        assert!(res.is_ok());
    }
}

#[test]
fn test_syft() {
    let path = Path::new("cache");
    recurse_dir(path.to_path_buf(), SyftVisitor);
}
