use std::collections::LinkedList;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use std::path::PathBuf;

use serde::Serialize;

use crate::format::Error;

/// A simple function to write a serializable object to a json file.
#[allow(unused)]
pub fn write_json<O: ?Sized + Serialize, P: AsRef<Path>>(path: P, val: &O) -> Result<(), Error> {
    let file = File::create(path.as_ref()).map_err(Error::Io)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer(writer, val)
        .map_err(Error::Serde)
}

#[allow(unused)]
pub fn write_table<O, Header, Rows, RowItem>(out: &mut O, header: Header, rows: Rows) -> Result<(), std::io::Error>
    where O: std::io::Write,
          Rows: IntoIterator<Item=RowItem>,
          RowItem: IntoIterator<Item=String>,
          Header: IntoIterator<Item=String> {
    {
        let mut lengths: Vec<usize> = header.into_iter().map(|s| s.len() + 2).collect();
        let rows = rows
            .into_iter()
            .map(|v| v.into_iter())
            .map(|v| v.collect::<Vec<_>>())
            .map(|v| {
                assert_eq!(v.len(), lengths.len());
                for (i, v) in v.iter().enumerate() {
                    lengths[i] = std::cmp::max(lengths[i], v.len() + 2);
                }
                v
            })
            .collect::<Vec<_>>();

        write!(out, "┌");
        for (i, len) in lengths.iter().enumerate() {
            if i > 0 {
                write!(out, "┬");
            }
            write!(out, "{:─<1$}", "─", len + 2);
        }
        writeln!(out, "┐");

        for (i, row) in rows.iter().enumerate() {
            if i > 0 {
                write!(out, "├");
                for (i, len) in lengths.iter().enumerate() {
                    if i > 0 {
                        write!(out, "┼");
                    }
                    write!(out, "{:─<1$}", "─", len + 2);
                }
                writeln!(out, "┤");
            }

            write!(out, "│");
            for (i, row) in row.iter().enumerate() {
                if i > 0 {
                    write!(out, "│");
                }
                write!(out, " {:<1$}", row, lengths[i] + 1);
            }
            writeln!(out, "│");
        }
        write!(out, "└");
        for (i, len) in lengths.iter().enumerate() {
            if i > 0 {
                write!(out, "┴");
            }
            write!(out, "{:─<1$}", "─", len + 2);
        }
        writeln!(out, "┘");

        Ok(())
    }
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
                        if let Some(val) = self.matches(&path) {
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