use crate::{console_log, init_panic_hook, input::Membership, Fq, Fr, NovaProof, Params, G1, G2};
use ff::PrimeField;
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use js_sys::{Array, Number, Uint8Array};
use nova_scotia::{
    circom::reader::load_r1cs, continue_recursive_circuit, create_recursive_circuit, FileLocation,
};
use std::io::{Read, Write};
use wasm_bindgen::prelude::*;

/** Verify a proof */
#[wasm_bindgen]
pub async fn verify_proof(params_string: String, proof_string: String, num_steps: Number) -> Array {
    // deserialize pp file
    let params: Params = serde_json::from_str(&params_string).unwrap();

    // deserialize proof
    let proof: NovaProof = serde_json::from_str(&proof_string).unwrap();

    // parse num steps
    let num_steps = num_steps.as_f64().unwrap() as usize;

    // create z_0 values
    let z0_primary = vec![Fr::from(0); 4];
    let z0_secondary = vec![Fq::from(0)];
    // verify proof
    let res = proof
        .verify(&params, num_steps, &z0_primary, &z0_secondary)
        .unwrap()
        .0;
    // marshall results into js values
    let arr = Array::new_with_length(4);
    for (index, item) in res.into_iter().enumerate() {
        arr.set(
            index as u32,
            JsValue::from_str(&hex::encode(item.to_bytes())),
        );
    }

    arr
}

/**
 * Generates the first fold in a proof
 *
 * @param r1cs_url - the url of the r1cs file to load
 * @param wasm_url - the url of the wasm file to load
 * @param params_string - the stringified public parameters file
 * @param root - the root of the tree to prove membership in
 * @param membership_string - the stringified membership inputs
 **/
#[wasm_bindgen]
pub async fn generate_proof(
    r1cs_url: String,
    wasm_url: String,
    params_string: String,
    root: String,
    membership_string: String,
) -> String {
    init_panic_hook();
    // get r1cs
    // can't be deserialized without adding code upstream so download every time :/
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::URL(r1cs_url)).await;
    // deserialize the public params
    let params: Params = serde_json::from_str(&params_string).unwrap();
    // set location of the remote witcalc wasm file
    let witness_generator_wasm = FileLocation::URL(wasm_url);

    // deserialize the private input (membership inputs)
    let membership: Membership = serde_json::from_str(&membership_string).unwrap();

    // format for circom
    let private_inputs = membership.to_inputs();

    // decode root
    let bytes: [u8; 32] = hex::decode(root).unwrap().try_into().unwrap();
    let root = Fr::from_repr(bytes).unwrap();
    // define z0_primary
    let start_public_input = vec![root, Fr::from(0)];

    // compute the folding the proof
    let proof = create_recursive_circuit(
        witness_generator_wasm,
        r1cs,
        vec![private_inputs],
        start_public_input.clone(),
        &params,
    )
    .await
    .unwrap();
    console_log!("Success folding first membership!");

    // return the stringified proof
    return serde_json::to_string(&proof).unwrap();
}

/**
 * Compute the next step of a proof
 *
 * @param params_string - the stringified public parameters file
 * @param proof_string - the stringified proof file
 * @param membership_string - the stringified membership inputs
 * @param zi_primary - the step_out of previous proof and step_in for this proof
 * @return - the stringified proof file
 */
#[wasm_bindgen]
pub async fn continue_proof(
    r1cs_url: String,
    wasm_url: String,
    params_string: String,
    proof_string: String,
    membership_string: String,
    zi_primary: Array,
) -> String {
    init_panic_hook();
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::URL(r1cs_url)).await;
    // deserialize the public params
    let params: Params = serde_json::from_str(&params_string).unwrap();
    // set location of the remote witcalc wasm file
    let witness_generator_wasm = FileLocation::URL(wasm_url);

    // deserialize the private input (membership inputs)
    let membership: Membership = serde_json::from_str(&membership_string).unwrap();

    // format for circom
    let private_inputs = vec![membership.to_inputs()];

    // deserialize the previous fold to build from
    let mut proof: NovaProof = serde_json::from_str(&proof_string).unwrap();

    // parse the zi_primary
    let mut zi_primary_vec: Vec<Fr> = vec![];
    for i in 0..2 {
        let value = zi_primary.get(i as u32).as_string().unwrap();
        let bytes: [u8; 32] = hex::decode(value).unwrap().try_into().unwrap();
        zi_primary_vec.push(Fr::from_repr(bytes).unwrap());
    }

    // define z0_primary
    let start_public_input = vec![zi_primary_vec[0], Fr::from(0)];

    // continue the proof
    continue_recursive_circuit(
        &mut proof,
        zi_primary_vec,
        witness_generator_wasm,
        r1cs,
        private_inputs,
        start_public_input,
        &params,
    )
    .await
    .unwrap();

    console_log!("Success continuing membership fold!");

    // return the stringified proof
    return serde_json::to_string(&proof.clone()).unwrap();
}

/**
 * Obfuscate a proof by adding in random data to the witness
*/
#[wasm_bindgen]
pub async fn obfuscate_proof(
    r1cs_url: String,
    wasm_url: String,
    params_string: String,
    proof_string: String,
    zi_primary: Array,
) -> String {
    init_panic_hook();

    // load the r1cs from remote source
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::URL(r1cs_url)).await;
    // deserialize the public params
    let params: Params = serde_json::from_str(&params_string).unwrap();
    // set location of the remote witcalc wasm file
    let witness_generator_wasm = FileLocation::URL(wasm_url);

    // get a random private input to chaff the proof
    let private_inputs = vec![Membership::chaff()];

    // deserialize the previous fold to build from
    let mut proof: NovaProof = serde_json::from_str(&proof_string).unwrap();

    // parse the zi_pri: usizemary
    let mut zi_primary_vec: Vec<Fr> = vec![];
    for i in 0..2 {
        let value = zi_primary.get(i as u32).as_string().unwrap();
        let bytes: [u8; 32] = hex::decode(value).unwrap().try_into().unwrap();
        zi_primary_vec.push(Fr::from_repr(bytes).unwrap());
    }

    // define z0_primary
    let start_public_input = vec![zi_primary_vec[0], Fr::from(0)];

    // continue the proof with chaff step
    continue_recursive_circuit(
        &mut proof,
        zi_primary_vec,
        witness_generator_wasm,
        r1cs,
        private_inputs,
        start_public_input,
        &params,
    )
    .await
    .unwrap();

    console_log!("Success adding chaff to membership fold!");

    // return the stringified proof
    return serde_json::to_string(&proof.clone()).unwrap();
}

/**
 * Gzip compress a proof
 *
 * @param proof_string - the stringified json proof to compress
 * @return - the compressed proof as a Uint8Array
 */
#[wasm_bindgen]
pub fn compress_proof(proof: String) -> Uint8Array {
    // compress proof string
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(proof.as_bytes()).unwrap();
    // return compressed proof
    let compressed = encoder.finish().unwrap();
    // convert to js compatible u8array
    Uint8Array::from(compressed.as_slice())
}

/**
 * Gzip decompress a proof
 *
 * @param compressed - the compressed proof as a Uint8Array
 * @return - the decompressed proof as a string
 */
#[wasm_bindgen]
pub fn decompress_proof(compressed: Uint8Array) -> String {
    // convert the proof to a u8 slice
    let compressed_bytes = compressed.to_vec();
    // inflate the proof from compressed bytes
    let mut decoder = GzDecoder::new(compressed_bytes.as_slice());
    let mut proof = String::new();
    decoder.read_to_string(&mut proof).unwrap();

    // return stringified proof
    proof
}
