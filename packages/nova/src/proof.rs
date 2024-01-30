use crate::NovaProof;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Read, Write};

/**
 * Compress a Nova Proof with flate2 for transit to the server and storage
 *
 * @param proof - the Nova Proof to compress
 * @return - the compressed proof
 */
pub fn compress_proof(proof: &NovaProof) -> Vec<u8> {
    // serialize proof to json
    let serialized = serde_json::to_string(&proof).unwrap();
    // compress serialized proof
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(serialized.as_bytes()).unwrap();
    // return compressed proof
    encoder.finish().unwrap()
}

/**
 * Decompress a Nova Proof with flate2 for transit to the server and storage
 *
 * @param proof - the compressed Nova Proof to decompress
 * @return - the decompressed proof
 */
pub fn decompress_proof(proof: &[u8]) -> NovaProof {
    // decompress the proof into the serialized json string
    let mut decoder = GzDecoder::new(proof);
    let mut serialized = String::new();
    decoder.read_to_string(&mut serialized).unwrap();
    // deserialize the proof
    serde_json::from_str(&serialized).unwrap()
}

/**
 * Write a Nova Proof to the filesystem
 *
 * @param proof - the Nova Proof to write to fs
 * @path - the filepath to save the proof to - includes filename
 */
pub fn write_proof(proof: &NovaProof, path: std::path::PathBuf) {
    // compress the proof
    let compressed_proof = compress_proof(proof);
    // write the proof to fs
    std::fs::write(path, compressed_proof).expect("Unable to write proof");
}

/**
 * Read a Nova Proof from the filesystem
 *
 * @param path - the filepath to read the proof from
 */
pub fn read_proof(path: std::path::PathBuf) -> NovaProof {
    // read the proof from fs
    let compressed_proof = std::fs::read(path).expect("Unable to read proof");
    // decompress the proof
    decompress_proof(&compressed_proof[..])
}
