mod spider;

use std::ffi::OsStr;
use std::path::Path;
use clap::*;
use plotters::backend::BitMapBackend;
use plotters::prelude::IntoDrawingArea;
use plotters::style::WHITE;
use scayl::{DeploymentScore, read_json};

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
        #[clap(long)]
        out: Option<String>,
    },
}

fn main() {
    let cli: Cli = Parser::parse();

    match cli.subcommand {
        Commands::Spider { file, out: image } => {
            let score: DeploymentScore = read_json(&file).unwrap();
            let image = image.unwrap_or_else(|| String::from("spider.png"));
            let path = Path::new(&image);
            match path.extension().and_then(OsStr::to_str) {
                None => panic!("Image file must have an extension"),
                Some("png" | "svg" | "jpg" | "jpeg" | "gif") => {
                    let image = BitMapBackend::new(path, (1024, 1024))
                        .into_drawing_area();
                    image.fill(&WHITE).unwrap();
                    spider::spider(&image, &score).unwrap();
                }
                Some(v) => panic!("Unsupported file format: .{}", v),
            };
        }
    };
}
