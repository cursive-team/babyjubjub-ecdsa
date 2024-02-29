use babyjubjub_ecdsa_nova::Params;
use clap::{Args, Parser, Subcommand};
use std::env::current_dir;
use std::time::Instant;
use babyjubjub_ecdsa_nova::{G1, G2};
use nova_scotia::{circom::reader::load_r1cs, create_public_params, FileLocation};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // generate params
    Params(ParamsArgs),
}

#[derive(Args)]
struct ParamsArgs {
    r1cs: Option<String>,
    output: Option<String>,
}

pub fn main() {
    let cli = Cli::parse();

    _ = match &cli.command {
        Commands::Params(cmd) => {
            // let root = current_dir().unwrap();
            // let r1cs_file = root.join(cmd.r1cs.clone().unwrap());
            // let output_file = root.join(cmd.output.clone().unwrap()).join("public_params.json");
            // println!("Babyjubjub-ECDSA-Nova: Generate public parameters from R1CS");
            // println!("Using R1CS file: {}", &r1cs_file.display());
            // println!("Saving artifact to {}", &output_file.display());
            // println!("Generating parameters (may take 30 seconds to 5 minutes)...");
            // // start timer
            // let start: Instant = Instant::now();

            // // load r1cs from fs
            // let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(r1cs_file));

            // // compute public parameters
            // let public_params: Params = create_public_params(r1cs.clone());

            // // log elapsed time to compute parameters
            // println!(
            //     "Public parameters generation completed- took {:?}. Saving...",
            //     start.elapsed()
            // );

            // // save public params to fs
            // let params_json = serde_json::to_string(&public_params).unwrap();
            // std::fs::write(&output_file, &params_json).unwrap();

            // // output completion message
            // println!("Saved public parameters to {}", &output_file.display());
        }
    }
}
