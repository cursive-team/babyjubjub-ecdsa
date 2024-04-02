#[cfg(target_family = "wasm")]
use js_sys::{Array, Number, Boolean};
use nova_scotia::{
    circom::reader::load_r1cs, continue_recursive_circuit, create_recursive_circuit, FileLocation,
    C1, C2, F, S,
};
use ff::PrimeField;
use nova_snark::{CompressedSNARK, ProverKey, VerifierKey};

pub const BASE_URL: &str = "https://coffee-perfect-shark-551.mypinata.cloud/ipfs/QmThS3qgTvtZtN5tyURpbgFtSQxC6mrvs4ijzjH8PSFKva";
pub const FILE_NAME: &str = "folded";

// use nova_snark::{RecursiveSnark};
use crate::{
    inputs::{get_example_input, Membership},
    Fq, Fr, NovaProof, Params, DEFAULT_TREE_DEPTH, G1, G2,
};
use console_error_panic_hook;
use wasm_bindgen::prelude::*;
pub use wasm_bindgen_rayon::init_thread_pool;

// https://github.com/dmpierre/zkconnect4/blob/main/zkconnect4-nova-wasm/src/wasm.rs#L15-L37
#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    // The `console.log` is quite polymorphic, so we can bind it with multiple
    // signatures. Note that we need to use `js_name` to ensure we always call
    // `log` in JS.
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_u32(a: u32);

    // Multiple arguments too!
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_many(a: &str, b: &str);

    type Performance;

    static performance: Performance;

    #[wasm_bindgen(method)]
    fn now(this: &Performance) -> f64;
}
macro_rules! console_log {
    // Note that this is using the `log` function imported above during
    // `bare_bones`
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

// extern crate console_error_panic_hook;
#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

/**
 * Get the public parameters file for the folding operation
 *
 * @return - the stringified public_params.json file
 */
#[wasm_bindgen]
pub async fn get_pp_file() -> String {
    let url = format!("{}/{}", BASE_URL, "public_params.json");
    reqwest::get(&url).await.unwrap().text().await.unwrap()
}

/**
 * Get the spartan proving key file for compression and zk
 *
 * @return - the stringified pk.json file
 */
#[wasm_bindgen]
pub async fn get_pk_file() -> String {
    let url = format!("{}/{}", BASE_URL, "pk.json");
    reqwest::get(&url).await.unwrap().text().await.unwrap()
}

/**
 * Get the spartan verification key file for verifying compressed spartan zk proof
 *
 * @return - the stringified vk.json file
 */
#[wasm_bindgen]
pub async fn get_vk_file() -> String {
    let url = format!("{}/{}", BASE_URL, "vk.json");
    reqwest::get(&url).await.unwrap().text().await.unwrap()
}

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

/** Generates a new proof */
#[wasm_bindgen]
pub async fn generate_proof(params_string: String, membership_string: String) -> String {
    init_panic_hook();
    // get r1cs
    // can't be deserialized without adding code upstream so download every time :/
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::URL(format!(
        "{}/{}.r1cs",
        BASE_URL, FILE_NAME
    )))
    .await;
    // deserialize the public params
    let params: Params = serde_json::from_str(&params_string).unwrap();
    // set location of the remote witcalc wasm file
    let witness_generator_wasm = FileLocation::URL(format!("{}/{}.wasm", BASE_URL, FILE_NAME));

    // deserialize the private input (membership inputs)
    let membership: Membership<DEFAULT_TREE_DEPTH> =
        serde_json::from_str(&membership_string).unwrap();

    // format for circom
    let private_inputs = membership.to_inputs();

    // define z0_primary
    let start_public_input = vec![Fr::from(0); 4];

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
    console_log!("Success folding membership!");

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
    params_string: String,
    proof_string: String,
    membership_string: String,
    zi_primary: Array,
) -> String {
    init_panic_hook();

    // get r1cs
    // can't be deserialized without adding code upstream so download every time :/
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::URL(format!(
        "{}/{}.r1cs",
        BASE_URL, FILE_NAME
    )))
    .await;
    // deserialize the public params
    let params: Params = serde_json::from_str(&params_string).unwrap();
    // set location of the remote witcalc wasm file
    let witness_generator_wasm = FileLocation::URL(format!("{}/{}.wasm", BASE_URL, FILE_NAME));

    // deserialize the private input (membership inputs)
    let membership: Membership<DEFAULT_TREE_DEPTH> =
        serde_json::from_str(&membership_string).unwrap();

    // format for circom
    let private_inputs = vec![membership.to_inputs()];

    // deserialize the previous fold to build from
    let mut proof: NovaProof = serde_json::from_str(&proof_string).unwrap();

    // parse the zi_pri: usizemary
    let mut zi_primary_vec: Vec<Fr> = vec![];
    for i in 0..4 {
        let value = zi_primary.get(i as u32).as_string().unwrap();
        let bytes: [u8; 32] = hex::decode(value).unwrap().try_into().unwrap();
        zi_primary_vec.push(Fr::from_repr(bytes).unwrap());
    }

    // define z0_primary
    let start_public_input = vec![Fr::from(0); 4];

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
    
    // return the stringified proof
    serde_json::to_string(&proof).unwrap()
}

#[wasm_bindgen]
pub async fn compress_to_spartan(
    params_string: String,
    proving_key_string: String,
    proof_string: String
) -> String {
    // deserialize the public params
    console_log!("Deserializing");
    let params: Params = serde_json::from_str(&params_string).unwrap();
    // deserialize the proving key
    let proving_key: ProverKey<G1, G2, C1<G1>, C2<G2>, S<G1>, S<G2>> = serde_json::from_str(&proving_key_string).unwrap();
    // deserialize the proof
    let proof: NovaProof = serde_json::from_str(&proof_string).unwrap();
    // compress the proof
    console_log!("Proving");
    let compressed_proof = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::prove(&params, &proving_key, &proof).unwrap();
    // return the stringified proof
    console_log!("Proving successful");
    serde_json::to_string(&compressed_proof).unwrap()
}

#[wasm_bindgen]
pub async fn verify_spartan(verifier_key_string: String, proof_string: String, iterations: Number) -> Array {
    // deserialize the verifier key
    let vk: VerifierKey<G1, G2, C1<G1>, C2<G2>, S<G1>, S<G2>> = serde_json::from_str(&verifier_key_string).unwrap();

    // deserialize the proof
    let proof: CompressedSNARK::<G1, G2, C1<G1>, C2<G2>, S<G1>, S<G2>> = serde_json::from_str(&proof_string).unwrap();

    // parse num steps
    let num_steps = iterations.as_f64().unwrap() as usize;

    // set z0 secondary and start input
    let start_step_input = vec![Fr::from(0); 4];
    let z0_secondary = vec![Fq::from(0)];

    // verify the proof
    let res = proof.verify(
        &vk,
        num_steps,
        start_step_input,
        z0_secondary
    ).unwrap().0;

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



use wasm_bindgen_test::*;

#[wasm_bindgen_test]
async fn fold_3_test() {
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_worker);

    // note: uses same membership 5 times

    // download public params
    let start = performance.now();
    let pp_str = get_pp_file().await;
    let end = performance.now();
    console_log!("Time to complete params download: {}ms", end - start);

    // get the membership inputs
    let url = format!("{}/{}", BASE_URL, "example.json");
    let resp = reqwest::get(url)
        .await
        .unwrap()
        .json::<Membership<8>>()
        .await
        .unwrap();
    let membership_string = serde_json::to_string(&resp).unwrap();

    // compute proof 1
    let start = performance.now();
    let proof: String = generate_proof(pp_str.clone(), membership_string.clone()).await;
    let end = performance.now();
    console_log!("Time to complete proof 1: {}ms", end - start);

    // verify proof 1
    let start = performance.now();
    let zi_primary = verify_proof(pp_str.clone(), proof.clone(), Number::from(1)).await;
    let end = performance.now();
    console_log!("Time to complete verification 1: {}ms", end - start);

    // compute proof 2
    let start = performance.now();
    let proof: String = continue_proof(pp_str.clone(), proof, membership_string.clone(), zi_primary).await;
    let end = performance.now();
    console_log!("Time to complete proof 2: {}ms", end - start);

    // verify proof 2
    let start = performance.now();
    let zi_primary = verify_proof(pp_str.clone(), proof.clone(), Number::from(2)).await;
    let end = performance.now();
    console_log!("Time to complete verification 2: {}ms", end - start);

    // compute proof 3
    let start = performance.now();
    let proof: String = continue_proof(pp_str.clone(), proof, membership_string.clone(), zi_primary).await;
    let end = performance.now();
    console_log!("Time to complete proof 3: {}ms", end - start);

    // verify proof 3
    let start = performance.now();
    let zi_primary = verify_proof(pp_str.clone(), proof.clone(), Number::from(3)).await;
    let end = performance.now();
    console_log!("Time to complete verification 2: {}ms", end - start);

    // retrieve proving key
    let start = performance.now();
    let pk = get_pk_file().await;
    let end = performance.now();
    console_log!("Time to retrieve pk: {}ms", end - start);

    // get verifier key
    let start = performance.now();
    let vk = get_vk_file().await;
    let end = performance.now();
    console_log!("Time to retrieve vk: {}ms", end - start);

    // compress into snark
    let start = performance.now();
    let compressed_proof = compress_to_spartan(pp_str.clone(), pk, proof.clone()).await;
    let end = performance.now();
    console_log!("Time to compress proof to spartan: {}ms", end - start);

    // verify snark
    let start = performance.now();
    let res = verify_spartan(vk, compressed_proof, Number::from(3)).await;
    let end = performance.now();
    console_log!("Time to verify spartan proof: {}ms", end - start);

    // print output
    let mut output: Vec<String> = vec![];
    for i in 0..4 {
        output.push(res.get(i as u32).as_string().unwrap());
    }
    console_log!("Root: {}", output[0]);
    console_log!("Pubkey Nullifier Randomness: {}", output[1]);
    console_log!("Signature Nullifier Randomness: {}", output[2]);
    console_log!("Number of signatures verified: {}", output[3]);
}