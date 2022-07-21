use std::collections::LinkedList;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use std::path::PathBuf;
use serde::Serialize;
use crate::format::Error;

/// A simple function to write a serializable object to a json file.
#[allow(unused)]
pub async fn write_json<O: ?Sized + Serialize, P: AsRef<Path>>(path: P, val: &O) -> Result<(), Error> {
    let file = File::create(path.as_ref()).map_err(Error::Io)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer(writer, val)
        .map_err(Error::Serde)
}

pub trait RecurseDir<T> {
    fn matches(&self, path: &PathBuf) -> Option<T>;

    fn recurse_dir<O, I: FromIterator<O>, F: Fn(PathBuf, T) -> O>(&self, path: PathBuf, visitor: F) -> I {
        let mut queue = LinkedList::new();
        queue.push_back(path);
        let mut vals = LinkedList::new();
        while let Some(next) = queue.pop_front() {
            if next.is_dir() {
                let entry = next.read_dir().unwrap();
                for e in entry {
                    let e = e.unwrap();
                    if e.path().is_dir() {
                        queue.push_back(e.path());
                    } else {
                        let path = e.path();
                        if let Some(val) =  self.matches(&path) {
                            vals.push_back(visitor(path, val));
                        }
                    }
                }
            } else {
                if let Some(val) = self.matches(&next) {
                    vals.push_back(visitor(next, val));
                }
            }
        }

        I::from_iter(vals.into_iter())
    }
}