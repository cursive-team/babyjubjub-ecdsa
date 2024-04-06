#!/bin/bash

# go to the wasm src directory
cd ../crates/bjj-ecdsa-nova-wasm

# build the wasm
wasm-pack build --target web --out-dir ../../pkg

# go to the pkg directory & remove the gitignore
cd ../../pkg && rm .gitignore

cd ..