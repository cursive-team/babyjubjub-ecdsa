use babyjubjub_ecdsa_nova::nova::{fold_bjj_ecdsa_memberships, get_r1cs};
use babyjubjub_ecdsa_nova::params::get_public_params;
use babyjubjub_ecdsa_nova::{DEFAULT_PARAMS_PATH, DEFAULT_R1CS_PATH, DEFAULT_WC_PATH, Fr, Fq, G1, G2};
use nova_snark::CompressedSNARK;
use nova_scotia::S;
use criterion::{criterion_group, criterion_main, Criterion};

fn benchmark(c: &mut Criterion) {
    let r1cs_path = String::from(DEFAULT_R1CS_PATH);
    let params_path = String::from(DEFAULT_PARAMS_PATH);
    let wc_path = String::from(DEFAULT_WC_PATH);
    let public_params = get_public_params(params_path);
    let r1cs = get_r1cs(r1cs_path);
    let iterations = 10;
    let proof = fold_bjj_ecdsa_memberships(&wc_path, &r1cs, &public_params, iterations).unwrap();
    let (pk, vk) = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::setup(&public_params).unwrap();
    c.bench_function("Compress a folded proof of 10 instances", |b| {
        b.iter(|| {
            
            let compressed_proof =
                CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::prove(&public_params, &pk, &proof)
                    .unwrap();
            // verify the proof
            let res = compressed_proof.verify(
                &vk,
                iterations,
                vec![Fr::from(0); 4],
                vec![Fq::from(0); 1],
            );
            // note: use z0_primary to set the root and ensure proof starts at 0 to have proof of N statements. can probably remove iterator count even and use use the num_steps to demonstrate # of memberships
            assert!(res.is_ok());
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark
}
criterion_main!(benches);
