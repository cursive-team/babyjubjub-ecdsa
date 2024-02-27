use js_sys::Array;
use nova_scotia::{
    circom::reader::load_r1cs, create_recursive_circuit, FileLocation, C1, C2, F, S,
};

pub const BASE_URL: &str = "/home/jpag/Workground/EF/babyjubjub-ecdsa/packages/nova/circuits/artifacts/";

// use nova_snark::{RecursiveSnark};
use crate::{NovaProof, Params};
use wasm_bindgen::prelude::*;
pub use wasm_bindgen_rayon::init_thread_pool;

/** Generates a new proof */
#[wasm_bindgen]
pub async fn generate_proof(pp_chunks: Array, game_string: String) -> String {
    init_panic_hook();
    let mut pp_str = String::new();
    for i in 0..11 {
        pp_str.push_str(&pp_chunks.get(i).as_string().unwrap());
    }

    let r1cs = load_r1cs::<G1, G2>(&FileLocation::URL(
        BUCKET_URL.to_string().clone() + FILE_NAME + ".r1cs",
    ))
    .await;
    let witness_generator_wasm =
        FileLocation::URL(BUCKET_URL.to_string().clone() + FILE_NAME + ".wasm");

    let game: Game = serde_json::from_str(&game_string).unwrap();
    let n_turns = game.board.len();
    let initial_root = F::<G1>::from_raw(get_initial_game_root(&game));
    let start_public_input = vec![
        initial_root,
        F::<G1>::from(game.initialStepIn.1),
        F::<G1>::from(game.initialStepIn.2),
    ];
    let private_inputs = create_private_inputs(&game, n_turns);

    let pp: PublicParams<G1, G2, _, _> = serde_json::from_str(&pp_str).unwrap();

    console_log!(
        "Number of constraints per step (primary circuit): {}",
        pp.num_constraints().0
    );
    console_log!(
        "Number of constraints per step (secondary circuit): {}",
        pp.num_constraints().1
    );
    console_log!(
        "Number of variables per step (primary circuit): {}",
        pp.num_variables().0
    );
    console_log!(
        "Number of variables per step (secondary circuit): {}",
        pp.num_variables().1
    );

    console_log!("Creating a RecursiveSNARK...");

    let recursive_snark = create_recursive_circuit(
        witness_generator_wasm,
        r1cs,
        private_inputs,
        start_public_input.clone(),
        &pp,
    )
    .await
    .unwrap();

    // TODO: empty?
    let z0_secondary = [F::<G2>::from(0)];

    // verify the recursive SNARK
    console_log!("Verifying a RecursiveSNARK...");
    let res = recursive_snark.verify(&pp, n_turns, &start_public_input, &z0_secondary);
    assert!(res.is_ok());

    // produce a compressed SNARK
    console_log!("Generating a CompressedSNARK using Spartan with IPA-PC...");

    let (pk, vk) = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::setup(&pp).unwrap();
    let res = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::prove(&pp, &pk, &recursive_snark);
    assert!(res.is_ok());
    let compressed_snark = res.unwrap();
    let res = compressed_snark.verify(
        &vk,
        n_turns,
        start_public_input.to_vec(),
        z0_secondary.to_vec(),
    );
    assert!(res.is_ok());
    return serde_json::to_string(&compressed_snark).unwrap();
}

/** Continues building from an existing proof */
#[wasm_bindgen]
pub async fn continue_proof(artifact_url: String, pp_chunks: Array, proof_string: String, game_string: String) -> String {
    init_panic_hook();
    let mut pp_str = String::new();
    for i in 0..11 {
        pp_str.push_str(&pp_chunks.get(i).as_string().unwrap());
    }

    let r1cs = load_r1cs::<G1, G2>(&FileLocation::URL(
        BUCKET_URL.to_string().clone() + FILE_NAME + ".r1cs",
    ))
    .await;
    let witness_generator_wasm =
        FileLocation::URL(BUCKET_URL.to_string().clone() + FILE_NAME + ".wasm");

    let game: Game = serde_json::from_str(&game_string).unwrap();
    let n_turns = game.board.len();
    let initial_root = F::<G1>::from_raw(get_initial_game_root(&game));
    let start_public_input = vec![
        initial_root,
        F::<G1>::from(game.initialStepIn.1),
        F::<G1>::from(game.initialStepIn.2),
    ];
    let private_inputs = create_private_inputs(&game, n_turns);

    let pp: PublicParams<G1, G2, _, _> = serde_json::from_str(&pp_str).unwrap();

    console_log!(
        "Number of constraints per step (primary circuit): {}",
        pp.num_constraints().0
    );
    console_log!(
        "Number of constraints per step (secondary circuit): {}",
        pp.num_constraints().1
    );
    console_log!(
        "Number of variables per step (primary circuit): {}",
        pp.num_variables().0
    );
    console_log!(
        "Number of variables per step (secondary circuit): {}",
        pp.num_variables().1
    );

    console_log!("Creating a RecursiveSNARK...");

    let recursive_snark = create_recursive_circuit(
        witness_generator_wasm,
        r1cs,
        private_inputs,
        start_public_input.clone(),
        &pp,
    )
    .await
    .unwrap();

    // TODO: empty?
    let z0_secondary = [F::<G2>::from(0)];

    // verify the recursive SNARK
    console_log!("Verifying a RecursiveSNARK...");
    let res = recursive_snark.verify(&pp, n_turns, &start_public_input, &z0_secondary);
    assert!(res.is_ok());

    // produce a compressed SNARK
    console_log!("Generating a CompressedSNARK using Spartan with IPA-PC...");

    let (pk, vk) = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::setup(&pp).unwrap();
    let res = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::prove(&pp, &pk, &recursive_snark);
    assert!(res.is_ok());
    let compressed_snark = res.unwrap();
    let res = compressed_snark.verify(
        &vk,
        n_turns,
        start_public_input.to_vec(),
        z0_secondary.to_vec(),
    );
    assert!(res.is_ok());
    return serde_json::to_string(&compressed_snark).unwrap();
}

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
}
macro_rules! console_log {
    // Note that this is using the `log` function imported above during
    // `bare_bones`
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

extern crate console_error_panic_hook;
#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub async fn download_params(url: String) -> String {
    let pp_str = get_chunked_pp_file(&url, &prefix, 11).await;
    let pp = serde_json::from_str::<PublicParams<G1, G2, C1<G1>, C2<G2>>>(&pp_str).unwrap();
    console_log!(
        "Number of constraints per step (primary circuit): {}",
        pp.num_constraints().0
    );
    return pp_str;
}
