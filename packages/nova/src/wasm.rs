#[cfg(target_family = "wasm")]
use js_sys::Array;
use nova_scotia::{
    circom::reader::load_r1cs, create_recursive_circuit, FileLocation, C1, C2, F, S,
};

// pub const BASE_URL: &str =
//     "/home/jpag/Workground/EF/babyjubjub-ecdsa/packages/nova/circuits/artifacts/";

pub const BASE_URL: &str = "https://pink-grieving-spoonbill-655.mypinata.cloud/ipfs/QmUQd6cnPz2YfJh7WQ8XLF6a8str35t5YfKQsSd6RFmLs5";

pub const FILE_NAME: &str = "folded";

// use nova_snark::{RecursiveSnark};
use crate::{
    inputs::{get_example_input, Membership},
    Fr, NovaProof, Params, DEFAULT_TREE_DEPTH, G1, G2,
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

// #[wasm_bindgen]
// pub async fn download_params(url: String) -> String {
//     let pp_str = get_chunked_pp_file(BASE_URL.to_string().clone() + "public_params.json", &prefix, 11).await;
//     let pp = serde_json::from_str::<PublicParams<G1, G2, C1<G1>, C2<G2>>>(&pp_str).unwrap();
//     console_log!(
//         "Number of constraints per step (primary circuit): {}",
//         pp.num_constraints().0
//     );
//     return pp_str;
// }

#[wasm_bindgen]
pub async fn get_pp_file() -> String {
    let url = format!("{}/{}", BASE_URL, "public_params.json");
    let pp = reqwest::get(&url).await.unwrap().text().await.unwrap();
    return pp;
}

/** Generates a new proof */
#[wasm_bindgen]
pub async fn generate_proof(params_string: String, membership_string: String) -> String {
    init_panic_hook();

    let r1cs = load_r1cs::<G1, G2>(&FileLocation::URL(format!(
        "{}/{}.r1cs",
        BASE_URL, FILE_NAME
    )))
    .await;


    let witness_generator_wasm = FileLocation::URL(format!("{}/{}.wasm", BASE_URL, FILE_NAME));

    let membership: Membership<DEFAULT_TREE_DEPTH> =
        serde_json::from_str(&membership_string).unwrap();


    let private_inputs = membership.to_inputs();

    let start_public_input = vec![Fr::from(0); 4];
    let start = performance.now();
    let params: Params = serde_json::from_str(&params_string).unwrap();
    let end = performance.now();
    console_log!("Time to complete params marshall: {}", end - start);

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

    return serde_json::to_string(&proof).unwrap();
}

// #[wasm_bindgen]
// pub async fn continue_proof(params_string: String, membership_string: String, proof_string: String) -> String {
//     init_panic_hook();

//     // get r1cs
//     let r1cs = load_r1cs::<G1, G2>(&FileLocation::URL(format!(
//         "{}/{}.r1cs",
//         BASE_URL, FILE_NAME
//     )))
//     .await;

//     // get witness generator
//     let witness_generator_wasm = FileLocation::URL(format!("{}/{}.wasm", BASE_URL, FILE_NAME));

//     // deserialize membership
//     let membership: Membership<DEFAULT_TREE_DEPTH> =
//         serde_json::from_str(&membership_string).unwrap();
//     let private_inputs = membership.to_inputs();
// }

// pub async fn verify_proof(params_string: String, proof_string: String) -> St
// /** Continues building from an existing proof */
// #[wasm_bindgen]
// pub async fn continue_proof(artifact_url: String, pp_chunks: Array, proof_string: String, game_string: String) -> String {
//     init_panic_hook();
//     let mut pp_str = String::new();
//     for i in 0..11 {
//         pp_str.push_str(&pp_chunks.get(i).as_string().unwrap());
//     }

//     let r1cs = load_r1cs::<G1, G2>(&FileLocation::URL(
//         BUCKET_URL.to_string().clone() + FILE_NAME + ".r1cs",
//     ))
//     .await;
//     let witness_generator_wasm =
//         FileLocation::URL(BUCKET_URL.to_string().clone() + FILE_NAME + ".wasm");

//     let game: Game = serde_json::from_str(&game_string).unwrap();
//     let n_turns = game.board.len();
//     let initial_root = F::<G1>::from_raw(get_initial_game_root(&game));
//     let start_public_input = vec![
//         initial_root,
//         F::<G1>::from(game.initialStepIn.1),
//         F::<G1>::from(game.initialStepIn.2),
//     ];
//     let private_inputs = create_private_inputs(&game, n_turns);

//     let pp: PublicParams<G1, G2, _, _> = serde_json::from_str(&pp_str).unwrap();

//     console_log!(
//         "Number of constraints per step (primary circuit): {}",
//         pp.num_constraints().0
//     );
//     console_log!(
//         "Number of constraints per step (secondary circuit): {}",
//         pp.num_constraints().1
//     );
//     console_log!(
//         "Number of variables per step (primary circuit): {}",
//         pp.num_variables().0
//     );
//     console_log!(
//         "Number of variables per step (secondary circuit): {}",
//         pp.num_variables().1
//     );

//     console_log!("Creating a RecursiveSNARK...");

//     let recursive_snark = create_recursive_circuit(
//         witness_generator_wasm,
//         r1cs,
//         private_inputs,
//         start_public_input.clone(),
//         &pp,
//     )
//     .await
//     .unwrap();

//     // TODO: empty?
//     let z0_secondary = [F::<G2>::from(0)];

//     // verify the recursive SNARK
//     console_log!("Verifying a RecursiveSNARK...");
//     let res = recursive_snark.verify(&pp, n_turns, &start_public_input, &z0_secondary);
//     assert!(res.is_ok());

//     // produce a compressed SNARK
//     console_log!("Generating a CompressedSNARK using Spartan with IPA-PC...");

//     let (pk, vk) = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::setup(&pp).unwrap();
//     let res = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::prove(&pp, &pk, &recursive_snark);
//     assert!(res.is_ok());
//     let compressed_snark = res.unwrap();
//     let res = compressed_snark.verify(
//         &vk,
//         n_turns,
//         start_public_input.to_vec(),
//         z0_secondary.to_vec(),
//     );
//     assert!(res.is_ok());
//     return serde_json::to_string(&compressed_snark).unwrap();
// }

use wasm_bindgen_test::*;

// #[wasm_bindgen_test]
// async fn load_r1cs_and_pp() {
//     wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
//     // let r1cs = load_r1cs::<G1, G2>(&FileLocation::URL(format!(
//     //     "{}{}.r1cs",
//     //     BASE_URL, FILE_NAME
//     // )))
//     // .await;
//     // let pp_str = get_pp_file().await;
//     // let params: Params = serde_json::from_str(&pp_str).unwrap();
// }

#[wasm_bindgen_test]
async fn test_test() {
    console_log!("This is a test to see if console will tell me to fuck off");
}

#[wasm_bindgen_test]
async fn compute_snark() {
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_worker);
    // get artifacts
    // let r1cs = load_r1cs::<G1, G2>(&FileLocation::URL(format!(
    //     "{}{}.r1cs",
    //     BASE_URL, FILE_NAME
    // )))
    // .await;
    // Start timing
    let start = performance.now();
    let pp_str = get_pp_file().await;
    let end_download_pp = performance.now();
    console_log!("Time to complete params download: {}", end_download_pp - start);
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

// #[wasm_bindgen_test]
// async fn get_json() {
//     wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_worker);
//     let url = "https://pink-grieving-spoonbill-655.mypinata.cloud/ipfs/QmQsgDYfoc5sb74vfnJHMHLZ9G8iECke1VFbrkZHsRdh1e";
//     // let file = std::fs::read_to_string(path).unwrap();
//     let x = reqwest::get(url).await.unwrap().text().await.unwrap();
//     console_log!("{}", x);
//     let membership: Membership<8> = serde_json::from_str(&x).unwrap();
//     println!("Membership: {:#?}", membership);
// }
