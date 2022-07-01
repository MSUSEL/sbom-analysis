#![allow(dead_code)]

mod base;
mod temporal;
mod environmental;

pub (in crate::cvss) fn roundup(v: f32) -> f32 {
    (v * 10.0).round() / 10.0
}

pub use base::*;
pub use temporal::*;
pub use environmental::*;