use babyjubjub_ecdsa_nova::nova::{
    fold_bjj_ecdsa_memberships, get_r1cs,
};
use babyjubjub_ecdsa_nova::params::get_public_params;
use babyjubjub_ecdsa_nova::{DEFAULT_PARAMS_PATH, DEFAULT_R1CS_PATH, DEFAULT_WC_PATH};
use criterion::{criterion_group, criterion_main, Criterion};

fn benchmark(c: &mut Criterion) {
    let r1cs_path = String::from(DEFAULT_R1CS_PATH);
    let params_path = String::from(DEFAULT_PARAMS_PATH);
    let wc_path = String::from(DEFAULT_WC_PATH);
    let public_params = get_public_params(params_path);
    let r1cs = get_r1cs(r1cs_path);
    let iterations = 100;

    c.bench_function("Fold 10 instances together", |b| {
        b.iter(|| {
            _ = fold_bjj_ecdsa_memberships(&wc_path, &r1cs, &public_params, iterations).unwrap();
        });
    });
}

criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark
}
criterion_main!(benches);
