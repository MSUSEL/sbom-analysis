use std::path::{Path, PathBuf};

use crate::{Grype, Syft, Trivy};
use crate::format::{GrypeFileFilter, read_file};
use crate::util::io::RecurseDir;

#[test]
fn test_grype() {
    let path = Path::new("cache");
    let _: Vec<_> = GrypeFileFilter.recurse_dir(path.to_path_buf(), |path, _| {
        let grype: Result<Grype, _> = read_file(path.clone());
        if let Err(e) = &grype {
            println!("{} -> {}", path.display().to_string(), e);
        }
        assert!(grype.is_ok());
    });
}


#[test]
fn test_syft() {
    struct SyftVisitor;

    impl RecurseDir<()> for SyftVisitor {
        fn matches(&self, path: &PathBuf) -> Option<()> {
            path.file_name()
                .filter(|v| v.to_string_lossy().to_string() == "syft.sbom.json")
                .map(|_| ())
        }
    }

    let path = Path::new("cache");
    let _: Vec<_> = SyftVisitor.recurse_dir(path.to_path_buf(), |path, _| {
        let syft: Result<Syft, _> = read_file(path);
        assert!(syft.is_ok());
    });
}


#[test]
fn test_trivy() {
    struct TrivyVisitor;

    impl RecurseDir<()> for TrivyVisitor {
        fn matches(&self, path: &PathBuf) -> Option<()> {
            path.file_name()
                .filter(|v| v.to_string_lossy().to_string() == "trivy.json")
                .map(|_| ())
        }
    }
    
    let path = Path::new("cache");
    let _: Vec<_> = TrivyVisitor.recurse_dir(path.to_path_buf(), |path, _| {
        let trivy: Result<Trivy, _> = read_file(path);
        assert!(trivy.is_ok());
    });
}