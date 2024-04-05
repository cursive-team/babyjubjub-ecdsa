use babyjubjub_ecdsa_nova::Params;
use clap::{Args, Parser, Subcommand};
use nova_snark::{CompressedSNARK, ProverKey, VerifierKey};
use std::env::current_dir;
use std::time::Instant;
use babyjubjub_ecdsa_nova::{G1, G2};
use nova_scotia::{circom::reader::load_r1cs, create_public_params, FileLocation, S, C1, C2};
use std::io::Write;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;

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
    // chunked params
    ChunkedParams(ChunkedParamsArgs),
    // chunked keys
    ChunkedKeys(ChunkedKeysArgs),
}

#[derive(Args)]
struct ParamsArgs {
    r1cs: String,
    output: String,
}

#[derive(Args)]
struct ChunkedParamsArgs {
    r1cs: String,
    output: String,
}

#[derive(Args)]
struct ChunkedKeysArgs {
    path: String,
}

#[cfg(not(target_family = "wasm"))]
pub fn main() {
    let cli = Cli::parse();

    _ = match &cli.command {
        Commands::Params(cmd) => {
            let root = current_dir().unwrap();
            // let r1cs_file = root.join(cmd.r1cs.clone().unwrap());
            // let params_output_file = root.join(cmd.output.clone().unwrap()).join("public_params.json");
            // let vk_output_file = root.join(cmd.output.clone().unwrap()).join("vk.json");
            // let pk_output_file = root.join(cmd.output.clone().unwrap()).join("pk.json");
            // println!("Babyjubjub-ECDSA-Nova: Generate public parameters from R1CS");
            // println!("Using R1CS file: {}", &r1cs_file.display());
            // println!("Saving artifact to {}", &params_output_file.display());
            // println!("Generating parameters (may take 30 seconds to 5 minutes)...");
            // // start timer
            // let start: Instant = Instant::now();

            // // load r1cs from fs
            // let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(r1cs_file));

            // // // compute public parameters
            // // let public_params: Params = create_public_params(r1cs.clone());

            // // // log elapsed time to compute parameters
            // // println!(
            // //     "Public parameters generation completed- took {:?}. Saving...",
            // //     start.elapsed()
            // // );

            // // // save public params to fs
            // // let params_json = serde_json::to_string(&public_params).unwrap();
            // // std::fs::write(&params_output_file, &params_json).unwrap();

            // let params = std::fs::read_to_string(&params_output_file).unwrap();
            // let public_params: Params = serde_json::from_str(&params).unwrap();

            // // build the compressed snark vk and pk
            // println!("Computing compressed snark proving and verifying keys");
            // let (pk, vk) = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::setup(&public_params).unwrap();
            // let pk_str = serde_json::to_string(&pk).unwrap();
            // std::fs::write(&pk_output_file, &pk_str).unwrap();

            // let vk_str = serde_json::to_string(&vk).unwrap();
            // let vk: VerifierKey<G1, G2, C1<G1>, C2<G2>, S<G1>, S<G2>> = serde_json::from_str(&vk_str).unwrap();            
            // std::fs::write(&vk_output_file, &vk_str).unwrap();

            // // output completion message
            // println!("Saved artifacts to {}", root.join(cmd.output.clone().unwrap()).display());
        },
        Commands::ChunkedParams(cmd) => {
            chunk_params(&cmd.r1cs, &cmd.output);
        },
        Commands::ChunkedKeys(cmd) => {
            chunk_keys(&cmd.path);
        }
    }
}

/**
 * Chunks the params into 10 files and also saves the full file
 */
#[cfg(not(target_family = "wasm"))]
pub fn chunk_params(r1cs: &String, output: &String) { 
    
    // load the r1cs
    let root = current_dir().unwrap();
    let r1cs_file = root.join(r1cs.clone());
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(r1cs_file));

    // make the params file if none exists
    let params_output_folder = root.join(output.clone()).join("params");
    if !params_output_folder.exists() {
        std::fs::create_dir_all(params_output_folder.clone()).unwrap();
    }

    // compute the full params
    let public_params: Params = create_public_params(r1cs.clone());
    
    // save the full params
    let params_json = serde_json::to_string(&public_params).unwrap();
    let full_params_path = params_output_folder.clone().join("params.json");
    std::fs::write(&full_params_path, &params_json).unwrap();

    // compress the params
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(params_json.as_bytes()).unwrap();
    let compressed_params = encoder.finish().unwrap();

    // chunk the params
    let chunk_size = (compressed_params.len() + 9) / 10;
    let chunks: Vec<&[u8]> = compressed_params.chunks(chunk_size).collect();

    // save chunks
    for (i, chunk) in chunks.iter().enumerate() {
        let chunk_path = params_output_folder.join(format!("params_{}.json", i));
        let mut file = std::fs::File::create(&chunk_path).expect("Unable to create file");
        file.write_all(chunk).expect("Unable to write data");
    };
}

/**
 * Chunks proving and verifying keys
 * 
 * @param path: the path to the public params / where to save chunked keys
 */
#[cfg(not(target_family = "wasm"))]
pub fn chunk_keys(path: &String) {
    // load the public params
    let root = current_dir().unwrap();
    let params_file = root.join(path.clone()).join("params.json");
    let params = std::fs::read_to_string(&params_file).unwrap();
    let public_params: Params = serde_json::from_str(&params).unwrap();

    // make the keys file if none exists
    let vk_output_folder = root.join(path.clone()).join("vk");
    if !vk_output_folder.exists() {
        std::fs::create_dir_all(vk_output_folder.clone()).unwrap();
    }
    let pk_output_folder = root.join(path.clone()).join("pk");
    if !pk_output_folder.exists() {
        std::fs::create_dir_all(pk_output_folder.clone()).unwrap();
    }

    // build the compressed snark vk and pk
    let (pk, vk) = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::setup(&public_params).unwrap();
    let pk_str = serde_json::to_string(&pk).unwrap();
    let vk_str = serde_json::to_string(&vk).unwrap();

    // compress the keys
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(pk_str.as_bytes()).unwrap();
    let compressed_pk = encoder.finish().unwrap();

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(vk_str.as_bytes()).unwrap();
    let compressed_vk = encoder.finish().unwrap();

    // chunk the keys
    let pk_chunk_size = (compressed_pk.len() + 9) / 10;
    let pk_chunks: Vec<&[u8]> = compressed_pk.chunks(pk_chunk_size).collect();
    let vk_chunk_size = (compressed_vk.len() + 9) / 10;
    let vk_chunks: Vec<&[u8]> = compressed_vk.chunks(vk_chunk_size).collect();

    // save chunks
    for (i, chunk) in pk_chunks.iter().enumerate() {
        let chunk_path = pk_output_folder.join(format!("pk_{}.json", i));
        let mut file = std::fs::File::create(&chunk_path).expect("Unable to create file");
        file.write_all(chunk).expect("Unable to write data");
    };

    for (i, chunk) in vk_chunks.iter().enumerate() {
        let chunk_path = vk_output_folder.join(format!("vk_{}.json", i));
        let mut file = std::fs::File::create(&chunk_path).expect("Unable to create file");
        file.write_all(chunk).expect("Unable to write data");
    };
}