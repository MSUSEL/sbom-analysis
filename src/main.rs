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
        Commands::Analyze { grype, syft, trivy, cyclone, context, file } => {
            if let Err(e) = analyze(grype, syft, trivy, cyclone, context, file).await {
                eprintln!("Error: {}", e);
            }
        }
        Commands::EnMass { path, context } => {
            en_mass(path, context).await;
        }
    }
}
// CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N
// CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N