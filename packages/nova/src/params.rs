use crate::{Params, G1, G2};
use nova_scotia::{circom::reader::load_r1cs, create_public_params, FileLocation};
use nova_snark::PublicParams;
use std::env::current_dir;
use std::time::Instant;

/**
 * Generate nova public parameters file and save to fs for reuse
 *
 * @param r1cs_path - relative path to the r1cs file to use to compute public params
 * @param output_path - relative path to save public params output json
 */
pub fn gen_params(r1cs_path: String, output_path: String) {
    // get file paths
    let root = current_dir().unwrap();
    let r1cs_file = root.join(r1cs_path);
    let output_file = root.join(output_path);
    println!("Folded bjj-membership: Generate public parameters from R1CS");
    println!("Using R1CS file: {}", &r1cs_file.display());
    println!("Saving artifact to {}", &output_file.display());
    println!("Generating parameters...");

    // start timer
    let start: Instant = Instant::now();

    // load r1cs from fs
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(r1cs_file));

    // compute public parameters
    let public_params: PublicParams<G1, G2, _, _> = create_public_params(r1cs.clone());

    // log elapsed time to compute parameters
    println!(
        "Computation completed- took {:?}. Saving...",
        start.elapsed()
    );

    // save public params to fs
    let params_json = serde_json::to_string(&public_params).unwrap();
    std::fs::write(&output_file, &params_json).unwrap();

    // output completion message
    println!("Saved public parameters to {}", &output_file.display());
}

/**
* Get public params for the grapevine circuit
*
* @param path - the relative path to the public params json file
* @return - the public parameters for proving/ verifying circuit execution
*/
pub fn get_public_params(path: String) -> Params {
    let filepath = current_dir().unwrap().join(path);
    let public_params_file = std::fs::read_to_string(filepath).expect("Unable to read file");
    serde_json::from_str(&public_params_file).expect("Incorrect public params format")
}
