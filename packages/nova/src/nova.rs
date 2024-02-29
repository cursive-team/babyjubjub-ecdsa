use super::inputs::get_example_input;
use super::{Fq, Fr, NovaProof, Params, G1, G2};
use nova_scotia::circom::{circuit::R1CS, reader::load_r1cs};
use nova_scotia::{create_recursive_circuit, FileLocation};
use nova_snark::errors::NovaError;
use serde_json::Value;
use std::collections::HashMap;
use std::env::current_dir;

/**
 * Load the r1cs file for the grapevine circuit
 *
 * @param path - the relative path to the r1cs file of the grapevine circuit (if none use default)
 * @return - the r1cs file for the grapevine circuit
 */
pub fn get_r1cs(path: String) -> R1CS<Fr> {
    let filepath = current_dir().unwrap().join(path);
    load_r1cs::<G1, G2>(&FileLocation::PathBuf(filepath))
}

/**
 * Folds many instances of babyjubjub ecdsa membership proofs
 * @dev THIS IS MOCKED. Instead of passing inputs to proof, we pass iterations and get the same demo inputs for each folded instance! This will be replaced
 *
 * @param wc_path - the relative path to the wasm file used to calculate witness for the circuit
 * @param r1cs - the r1cs file for the folded babyjubjub ecdsa membership circuit
 * @param public_params - the public parameters for proving/ verifying correctness of folding
 * @param iterations - the number of membership instances being folded together
 */
pub fn fold_bjj_ecdsa_memberships(
    wc_path: &String,
    r1cs: &R1CS<Fr>,
    public_params: &Params,
    iterations: usize,
) -> Result<NovaProof, std::io::Error> {
    let wc_filepath = current_dir().unwrap().join(wc_path);
    let mut private_inputs: Vec<HashMap<String, Value>> = vec![];
    for _ in 0..iterations {
        private_inputs.push(get_example_input());
    }
    let start_step_input = vec![Fr::from(0); 4];
    create_recursive_circuit(
        FileLocation::PathBuf(wc_filepath),
        r1cs.clone(),
        private_inputs,
        start_step_input,
        &public_params,
    )
}

/**
 * Verify correctness of folded babyjubjub ecdsa membership proofs
 *
 * @param proof - the proof of correctness of folding for all instances
 * @param public_params - the public parameters for proving/ verifying correctness of folding
 * @param iterations - the number of membership instances folded together
 */
pub fn verify_folded_bjj_ecdsa_memberships(
    proof: &NovaProof,
    public_params: &Params,
    iterations: usize,
) -> Result<(Vec<Fr>, Vec<Fq>), NovaError> {
    let start_step_input = [Fr::from(0); 4];
    let z0_secondary = [Fq::from(0)];
    proof.verify(public_params, iterations, &start_step_input, &z0_secondary)
}
#[cfg(test)]
mod test {
    use super::*;
    use crate::params::get_public_params;
    use crate::proof::write_proof;
    use crate::{DEFAULT_PARAMS_PATH, DEFAULT_R1CS_PATH, DEFAULT_WC_PATH};
    use nova_scotia::S;
    use nova_snark::CompressedSNARK;

    #[test]
    fn prove_one() {
        // load proving artifacts into memory
        let public_params = get_public_params(String::from(DEFAULT_PARAMS_PATH));
        let r1cs = get_r1cs(String::from(DEFAULT_R1CS_PATH));
        let wc_path = String::from(DEFAULT_WC_PATH);
        // prove the correctness of a instance
        let iterations = 1;
        let proof =
            fold_bjj_ecdsa_memberships(&wc_path, &r1cs, &public_params, iterations).unwrap();
        // verify the proof of correct folding
        let verified =
            verify_folded_bjj_ecdsa_memberships(&proof, &public_params, iterations).unwrap();
        let num_verified = verified.0[3];
        assert!(num_verified.eq(&Fr::from(1)));
        // write proof to fs
        let proof_path = std::env::current_dir()
            .unwrap()
            .join(format!("bjj_ecdsa_membership_fold_{}.gz", iterations));
        write_proof(&proof, proof_path.clone());
    }

    #[test]
    fn prove_5() {
        // load proving artifacts into memory
        let public_params = get_public_params(String::from(DEFAULT_PARAMS_PATH));
        let r1cs = get_r1cs(String::from(DEFAULT_R1CS_PATH));
        let wc_path = String::from(DEFAULT_WC_PATH);
        // prove the correctness of a instance
        let iterations = 5;
        let proof =
            fold_bjj_ecdsa_memberships(&wc_path, &r1cs, &public_params, iterations).unwrap();
        // verify the proof of correct folding
        let verified =
            verify_folded_bjj_ecdsa_memberships(&proof, &public_params, iterations).unwrap();
        let num_verified = verified.0[3];
        println!("Num verified: {:?}", num_verified);
        // write proof to fs
        let proof_path = std::env::current_dir()
            .unwrap()
            .join(format!("bjj_ecdsa_membership_fold_{}.gz", iterations));
        write_proof(&proof, proof_path.clone());
    }

    #[test]
    fn prove_50() {
        // load proving artifacts into memory
        let public_params = get_public_params(String::from(DEFAULT_PARAMS_PATH));
        let r1cs = get_r1cs(String::from(DEFAULT_R1CS_PATH));
        let wc_path = String::from(DEFAULT_WC_PATH);
        // prove the correctness of a instance
        let iterations = 50;
        let proof =
            fold_bjj_ecdsa_memberships(&wc_path, &r1cs, &public_params, iterations).unwrap();
        // verify the proof of correct folding
        let verified =
            verify_folded_bjj_ecdsa_memberships(&proof, &public_params, iterations).unwrap();
        let num_verified = verified.0[3];
        println!("Num verified: {:?}", num_verified);
        // write proof to fs
        let proof_path = std::env::current_dir()
            .unwrap()
            .join(format!("bjj_ecdsa_membership_fold_{}.gz", iterations));
        write_proof(&proof, proof_path.clone());
    }

    #[test]
    fn compress_proof() {
        // load proving artifacts into memory
        let public_params = get_public_params(String::from(DEFAULT_PARAMS_PATH));
        let r1cs = get_r1cs(String::from(DEFAULT_R1CS_PATH));
        let wc_path = String::from(DEFAULT_WC_PATH);
        // prove the correctness of a instance
        let iterations = 2;
        let proof =
            fold_bjj_ecdsa_memberships(&wc_path, &r1cs, &public_params, iterations).unwrap();
        // verify the proof of correct folding
        _ = verify_folded_bjj_ecdsa_memberships(&proof, &public_params, iterations).unwrap();
        // compress the folded proof into a zero knowledge spartan snark
        let (pk, vk) = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::setup(&public_params).unwrap();
        let compressed_proof =
            CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::prove(&public_params, &pk, &proof)
                .unwrap();
        // verify the proof
        let res =
            compressed_proof.verify(&vk, iterations, vec![Fr::from(0); 4], vec![Fq::from(0); 1]);
        // note: use z0_primary to set the root and ensure proof starts at 0 to have proof of N statements. can probably remove iterator count even and use use the num_steps to demonstrate # of memberships
        assert!(res.is_ok());
        println!("Compressed proof verified: {:?}", res.unwrap());
        let serialized = serde_json::to_string(&compressed_proof).unwrap();
        let proof_path = std::env::current_dir().unwrap().join("compressed.proof");
        std::fs::write(proof_path, serialized).expect("Unable to write proof");
    }
}
