use clap::{Parser, Subcommand};

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
        grype: Option<String>,
        #[clap(long)]
        syft: Option<String>,
        #[clap(long)]
        trivy: Option<String>,
    }
}