// use babyjubjub_ecdsa_nova::params::{compress_params, decompress_params, get_public_params};
// use babyjubjub_ecdsa_nova::DEFAULT_PARAMS_PATH;

// use criterion::{criterion_group, criterion_main, Criterion};
// use std::time::Instant;

// fn benchmark(c: &mut Criterion) {
//     let params_path = String::from(DEFAULT_PARAMS_PATH);
//     let public_params = get_public_params(params_path);
//     let start: Instant = Instant::now();
//     let compressed_params = compress_params(&public_params);
//     println!("Compression took took {:?}.", start.elapsed());
//     let serialized = serde_json::to_string(&public_params)
//         .unwrap()
//         .as_bytes()
//         .to_vec();
//     println!("Size of uncompressed params: {:?} bytes", &serialized.len());
//     println!(
//         "Size of compressed params: {:?} bytes",
//         &compressed_params.len()
//     );
//     c.bench_function("Compress a folded proof of 10 instances", |b| {
//         b.iter(|| {
//             _ = decompress_params(&compressed_params);
//         });
//     });
// }

// criterion_group! {
//     name = benches;
//     config = Criterion::default().sample_size(10);
//     targets = benchmark
// }
// criterion_main!(benches);
