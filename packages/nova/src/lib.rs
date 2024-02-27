use nova_scotia::{circom::circuit::CircomCircuit, C1, C2, F};
use nova_snark::{provider, traits::circuit::TrivialTestCircuit, PublicParams, RecursiveSNARK};

pub mod inputs;
pub mod nova;
pub mod params;
pub mod proof;
#[cfg(target_family = "wasm")]
pub mod wasm;


pub type G1 = provider::bn256_grumpkin::bn256::Point;
pub type G2 = provider::bn256_grumpkin::grumpkin::Point;
pub type Fr = F<G1>;
pub type Fq = F<G2>;
pub type Params = PublicParams<G1, G2, C1<G1>, C2<G2>>;
pub type NovaProof = RecursiveSNARK<G1, G2, CircomCircuit<Fr>, TrivialTestCircuit<Fq>>;
pub const DEFAULT_PARAMS_PATH: &str = "circuits/artifacts/public_params.json";
pub const DEFAULT_R1CS_PATH: &str = "circuits/artifacts/folded.r1cs";
pub const DEFAULT_WC_PATH: &str = "circuits/artifacts/folded.wasm";
