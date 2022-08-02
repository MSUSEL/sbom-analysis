use clap::{Parser, Subcommand};

pub mod analyze;
pub mod en_mass;

pub use analyze::*;
pub use en_mass::*;

#[derive(Parser)]
#[clap(version, about, long_about = None, name="Scayl")]
#[clap(
    author = "Dillon Shaffer<dillon@molkars.dev> & Cynthia Rosas",
)]
pub struct Cli {
    #[clap(subcommand)]
    pub subcommand: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    #[clap(about = "Analyze a piece of software using various vulnerability formats.")]
    Analyze {
        #[clap(long)]
        grype: Vec<String>,
        #[clap(long)]
        syft: Vec<String>,
        #[clap(long)]
        trivy: Vec<String>,
        #[clap(long)]
        cyclone: Vec<String>,
        #[clap(long)]
        context: String,
        #[clap(long)]
        file: Option<String>,
    },
    #[clap(about = "Analyze a directory of software using various vulnerability formats.")]
    EnMass {
        #[clap(value_parser)]
        path: String,
        #[clap(long)]
        context: String,
    },
}