#!/bin/bash
cd circuits

# Make the artifacts directory if it doesn't exist

if [ ! -d "./artifacts" ]; then
  mkdir ./artifacts
fi

# Install circomlib for dependencies in circuits
echo "Installing circomlib dependencies for baby-jubjub-ecdsa folded circuit..."
yarn &> /dev/null

# Compile the circuits with necessary artifacts
echo "Compiling baby-jubjub-ecdsa folded circuit..."
circom ./baby-jubjub-ecdsa/folded.circom \
    --r1cs --wasm --sym \
    --output ./artifacts \
    --prime bn128 \
    &> /dev/null
mv ./artifacts/folded_js/folded.wasm ./artifacts/folded.wasm
rm -rf ./artifacts/folded_js

# Generate the public parameters
cd ..
echo "Generating public parameters for baby-jubjub-ecdsa folded circuit..."
cargo run --bin params_gen params ./circuits/artifacts/folded.r1cs ./circuits/artifacts/
echo "Setup for baby-jubjub-ecdsa folded circuit complete!"