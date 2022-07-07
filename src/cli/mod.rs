use clap::{Parser, Subcommand};

pub mod analyze;

#[derive(Parser)]
#[clap(version, about, long_about = None)]
pub struct Cli {
    #[clap(subcommand)]
    pub subcommand: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Analyze {
        #[clap(long)]
        grype: Vec<String>,
        #[clap(long)]
        syft: Vec<String>,
        #[clap(long)]
        trivy: Vec<String>,
        #[clap(long)]
        context: String,
        #[clap(long)]
        weights: Option<String>,
    }
}