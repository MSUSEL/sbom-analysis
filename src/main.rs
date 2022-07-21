extern crate tokio;

use clap::Parser;
use dotenv::dotenv;

use crate::cli::*;

mod cli;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let cli: Cli = Parser::parse();

    match &cli.subcommand {
        Commands::Analyze { grype, syft, trivy, context, file } => {
            analyze(grype, syft, trivy, context, file)
                .await
                .expect("Failed to analyze");
        }
        Commands::EnMass { path, context } => {
            en_mass(path, context).await;
        }
    }
}
