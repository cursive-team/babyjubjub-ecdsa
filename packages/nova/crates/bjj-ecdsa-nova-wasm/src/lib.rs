use nova_scotia::{circom::circuit::CircomCircuit, C1, C2, F};
use nova_snark::{provider, traits::circuit::TrivialTestCircuit, PublicParams, RecursiveSNARK};
use wasm_bindgen::prelude::*;

mod input;
mod nova;

pub type G1 = provider::bn256_grumpkin::bn256::Point;
pub type G2 = provider::bn256_grumpkin::grumpkin::Point;
pub type Fr = F<G1>;
pub type Fq = F<G2>;
pub type Params = PublicParams<G1, G2, C1<G1>, C2<G2>>;
pub type NovaProof = RecursiveSNARK<G1, G2, CircomCircuit<Fr>, TrivialTestCircuit<Fq>>;

pub const DEFAULT_TREE_DEPTH: usize = 8;

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



#[macro_export]
macro_rules! console_log {
    // Note that this is using the `log` function imported above during
    // `bare_bones`
    ($($t:tt)*) => (crate::log(&format_args!($($t)*).to_string()))
}

// extern crate console_error_panic_hook;
#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

/**
 * Get a random Fr element as a string for circuit input
 * 
 * @return - a random Fr element as a string
 */
#[wasm_bindgen]
pub fn random_fr() -> String {
    // get 31 bytes
    let mut buf = [0u8; 31];
    getrandom::getrandom(&mut buf).unwrap();
    // convert to 32 bytes
    let mut fr_buf = [0u8; 32];
    fr_buf[0..buf.len() - 1].copy_from_slice(&buf);
    fr_buf[31] = 0;
    // check valid fr
    hex::encode(fr_buf)
}

// pub const BASE_URL: &str = "https://coffee-perfect-shark-551.mypinata.cloud/ipfs/QmThS3qgTvtZtN5tyURpbgFtSQxC6mrvs4ijzjH8PSFKva";
// pub const FILE_NAME: &str = "folded";
// #[wasm_bindgen_test]
// async fn fold_3_test() {
//     wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_worker);

//     // note: uses same membership 5 times

//     // set urls
//     let r1cs_url = format!("{}/{}.r1cs", BASE_URL, FILE_NAME);
//     let wasm_url = format!("{}/{}.wasm", BASE_URL, FILE_NAME);

//     // download public params

//     let start = performance.now();
//     let pp_str = get_pp_file().await;
//     let end = performance.now();
//     console_log!("Time to complete params download: {}ms", end - start);

//     // get the membership inputs
//     let url = format!("{}/{}", BASE_URL, "example.json");
//     let resp = reqwest::get(url)
//         .await
//         .unwrap()
//         .json::<Membership<8>>()
//         .await
//         .unwrap();
//     let membership_string = serde_json::to_string(&resp).unwrap();

//     // compute proof 1
//     let start = performance.now();
//     let proof: String = generate_proof(
//         r1cs_url.clone(),
//         wasm_url.clone(),
//         pp_str.clone(),
//         membership_string.clone(),
//     )
//     .await;
//     let end = performance.now();
//     console_log!("Time to complete proof 1: {}ms", end - start);

//     // verify proof 1
//     let start = performance.now();
//     let zi_primary = verify_proof(pp_str.clone(), proof.clone(), Number::from(1)).await;
//     let end = performance.now();
//     console_log!("Time to complete verification 1: {}ms", end - start);

//     // compute proof 2
//     let start = performance.now();
//     let proof: String = continue_proof(
//         r1cs_url.clone(),
//         wasm_url.clone(),
//         pp_str.clone(),
//         proof,
//         membership_string.clone(),
//         zi_primary,
//     )
//     .await;
//     let end = performance.now();
//     console_log!("Time to complete proof 2: {}ms", end - start);

//     // verify proof 2
//     let start = performance.now();
//     let zi_primary = verify_proof(pp_str.clone(), proof.clone(), Number::from(2)).await;
//     let end = performance.now();
//     console_log!("Time to complete verification 2: {}ms", end - start);

//     // compute proof 3
//     let start = performance.now();
//     let proof: String = continue_proof(
//         r1cs_url.clone(),
//         wasm_url.clone(),
//         pp_str.clone(),
//         proof,
//         membership_string.clone(),
//         zi_primary,
//     )
//     .await;
//     let end = performance.now();
//     console_log!("Time to complete proof 3: {}ms", end - start);

//     // verify proof 3
//     let start = performance.now();
//     let zi_primary = verify_proof(pp_str.clone(), proof.clone(), Number::from(3)).await;
//     let end = performance.now();
//     console_log!("Time to complete verification 2: {}ms", end - start);

//     // retrieve proving key
//     let start = performance.now();
//     let pk = get_pk_file().await;
//     let end = performance.now();
//     console_log!("Time to retrieve pk: {}ms", end - start);

//     // get verifier key
//     let start = performance.now();
//     let vk = get_vk_file().await;
//     let end = performance.now();
//     console_log!("Time to retrieve vk: {}ms", end - start);

//     // compress into snark
//     let start = performance.now();
//     let compressed_proof = compress_to_spartan(pp_str.clone(), pk, proof.clone()).await;
//     let end = performance.now();
//     console_log!("Time to compress proof to spartan: {}ms", end - start);

//     // verify snark
//     let start = performance.now();
//     let res = verify_spartan(vk, compressed_proof, Number::from(3)).await;
//     let end = performance.now();
//     console_log!("Time to verify spartan proof: {}ms", end - start);

//     // print output
//     let mut output: Vec<String> = vec![];
//     for i in 0..4 {
//         output.push(res.get(i as u32).as_string().unwrap());
//     }
//     console_log!("Root: {}", output[0]);
//     console_log!("Pubkey Nullifier Randomness: {}", output[1]);
//     console_log!("Signature Nullifier Randomness: {}", output[2]);
//     console_log!("Number of signatures verified: {}", output[3]);
// }
