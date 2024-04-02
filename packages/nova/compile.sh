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

# Detect the operating system
OS=$(uname)

# Choose the Rust target based on the OS
case $OS in
  "Darwin")
    # macOS
    RUST_TARGET="x86_64-apple-darwin"
    ;;
  "Linux")
    # Linux
    RUST_TARGET="x86_64-unknown-linux-gnu"
    ;;
  *)
    echo "Unsupported OS: $OS"
    exit 1
    ;;
esac

# cargo run --target x86_64-unknown-linux-gnu --bin  params_gen params ./circuits/artifacts/folded.r1cs ./circuits/artifacts/
cargo run --target $RUST_TARGET --bin  params_gen params ./circuits/artifacts/folded.r1cs ./circuits/artifacts/
echo "Setup for baby-jubjub-ecdsa folded circuit complete!"