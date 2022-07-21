use clap::*;
use scayl::{read_json, VulnerabilityScore};

#[derive(Parser)]
struct Cli {
    #[clap(subcommand)]
    subcommand: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Spider {
        #[clap(value_parser)]
        file: String,
        #[clap(value_parser)]
        image: Option<String>,
    },
}

fn main() {
    let cli: Cli = Parser::parse();

    match cli.subcommand {
        Commands::Spider { file, .. } => {
            let _file: VulnerabilityScore = read_json(&file).unwrap();
        }
    }
}
