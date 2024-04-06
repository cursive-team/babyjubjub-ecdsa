use nova_scotia::{circom::circuit::CircomCircuit, C1, C2, F};
use nova_snark::{provider, traits::circuit::TrivialTestCircuit, PublicParams, RecursiveSNARK};
use wasm_bindgen::prelude::*;
use ff::PrimeField;

pub mod input;
pub mod nova;

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
    pub fn log(s: &str);

    // The `console.log` is quite polymorphic, so we can bind it with multiple
    // signatures. Note that we need to use `js_name` to ensure we always call
    // `log` in JS.
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    pub fn log_u32(a: u32);

    // Multiple arguments too!
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    pub fn log_many(a: &str, b: &str);

    pub type Performance;

    pub static performance: Performance;

    #[wasm_bindgen(method)]
    pub fn now(this: &Performance) -> f64;
}



#[macro_export]
macro_rules! console_log {
    // Note that this is using the `log` function imported above during
    // `bare_bones`
    ($($t:tt)*) => ($crate::log(&format_args!($($t)*).to_string()))
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
    // @todo: better method that uses rejection sampling
    // get 31 bytes
    let mut buf = [0u8; 31];
    getrandom::getrandom(&mut buf).unwrap();
    // convert to 32 bytes
    let mut fr_buf = [0u8; 32];
    fr_buf[0..buf.len()].copy_from_slice(&buf);
    fr_buf[31] = 0;
    // check valid fr
    Fr::from_repr(fr_buf).unwrap();
    // return hex string
    format!("0x{}", hex::encode(fr_buf))
}



