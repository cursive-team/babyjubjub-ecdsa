# Babyjubjub-ECDSA-Nova

## Installation
To use this repository, you at least need to compute the public parameters used to prove correctness of folded circuits:
```console
# Do this in the same folder as Cargo.toml, (/babyjubjub-ecdsa/packages/nova)
cargo run --bin params_gen params ./circuits/artifacts/folded.r1cs ./circuits/artifacts/
```
This file should be 101 Mb and can be readily recomputed (it is not a trusted setup) by the client

You can additionally recompile all circuit artifacts by running `./compile.sh` in the same directory as above.

You can check that `public_params.json` was correctly computed by ensuring the md5 checksum is `4fb86c7dd78dc5a4854e7eb675930a14`:
```console
md5sum ./circuits/artifacts/public_parameters.json
```

## What does it do?
@TODO once accumulation of public inputs figured out & compressed zkSNARK implemented

## Benchmarking
You can benchmark the efficacy of folding babyjubjub-ecdsa membership circuits together in batches of 10 or 100.

### Run benchmark commands
Benchmark folding 10 instances together:
```console
cargo bench --bench fold_10
```

Benchmark folding 100 instances together:
```console
cargo bench --bench fold_100
```

Benchmark compressing a folding proof into a succinct, zero knowledge Spartan proof:
```console
cargo bench --bench compress_fold
```

### Results
Benchmarked native (not wasm) on Intel(R) Core(TM) i7-4770K CPU @ 3.50GHz with 32 gb memory:

 - Folding 10 instances together, with sample size of 10: `time:   [50.788 s 51.480 s 52.090 s]`
 - Folding 100 instances together, with sample size of 10: TODO
 - Compressing a folded proof of 10 instances, with sample size of 10: `time:   [8.8837 s 8.9355 s 8.9889 s]`