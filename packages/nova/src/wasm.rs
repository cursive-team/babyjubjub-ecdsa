use ff::PrimeField;
#[cfg(target_family = "wasm")]
use js_sys::{Array, Number};
use nova_scotia::{
    circom::reader::load_r1cs, continue_recursive_circuit, create_recursive_circuit, FileLocation,
    C1, C2, F, S,
};

pub const BASE_URL: &str = "https://pink-grieving-spoonbill-655.mypinata.cloud/ipfs/QmUQd6cnPz2YfJh7WQ8XLF6a8str35t5YfKQsSd6RFmLs5";
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
    let pp = reqwest::get(&url).await.unwrap().text().await.unwrap();
    return pp;
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

use wasm_bindgen_test::*;

// #[wasm_bindgen_test]
async fn compute_snark() {
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_worker);
    // get artifacts
    // let r1cs = load_r1cs::<G1, G2>(&FileLocation::URL(format!(
    //     "{}{}.r1cs",
    //     BASE_URL, FILE_NAME
    // )))
    // .await;
    // Start timing
    let start: f64 = performance.now();
    let pp_str = get_pp_file().await;
    let end_download_pp = performance.now();
    console_log!(
        "Time to complete params download: {}",
        end_download_pp - start
    );
    // let witness_generator_wasm = FileLocation::URL(format!("{}{}.wasm", BASE_URL, FILE_NAME));
    // let private_input = vec![get_example_input()];

    let url = "https://pink-grieving-spoonbill-655.mypinata.cloud/ipfs/QmQsgDYfoc5sb74vfnJHMHLZ9G8iECke1VFbrkZHsRdh1e";
    // console_log!(format!("{}", url));

    let resp = reqwest::get(url)
        .await
        .unwrap()
        .json::<Membership<8>>()
        .await
        .unwrap();
    let membership_string = serde_json::to_string(&resp).unwrap();

    let start = performance.now();
    let proof: String = generate_proof(pp_str, membership_string).await;
    let end = performance.now();
    console_log!("Time to complete proof: {}", end - start);
    console_log!("Success building a proof");
}

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
    let url = "https://pink-grieving-spoonbill-655.mypinata.cloud/ipfs/QmQsgDYfoc5sb74vfnJHMHLZ9G8iECke1VFbrkZHsRdh1e";
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
}