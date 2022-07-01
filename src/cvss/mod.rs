#![allow(dead_code)]

pub use base::*;
pub use environmental::*;
pub use temporal::*;

mod base;
mod temporal;
mod environmental;

pub fn roundup(v: f32) -> f32 {
    (v * 10.0).round() / 10.0
}

