pragma circom 2.1.2;

include "./baby_jubjub_ecdsa.circom";
include "./tree.circom";
include "../../../node_modules/circomlib/circuits/poseidon.circom";

/**
 *  PubkeyMembership
 *  ================
 *  
 *  Checks that an inputted efficient ECDSA signature (definition and discussion 
 *  can be found at https://personaelabs.org/posts/efficient-ecdsa-1/) 
 *  is signed by a public key that is in a Merkle tree of public keys. Avoids the
 *  SNARK-unfriendly Keccak hash that must be performed when validating if the 
 *  public key is in a Merkle tree of addresses. Generates a signature nullifier 
 *  as a hash of the signature s value and the sigNullifierRandomness parameter. 
 *  Generates a public key nullifier as a hash of the public key hash and the
 *  pubKeyNullifierRandomness parameter. Also hashes the pubKeyNullifierRandomness
 *  parameter to ensure the same one is used across multiple proofs without revealing it.
 */
template PubKeyMembership(nLevels) {
    signal input s;
    signal input root;
    signal input Tx; 
    signal input Ty; 
    signal input Ux;
    signal input Uy;
    signal input pathIndices[nLevels];
    signal input siblings[nLevels];
    signal input sigNullifierRandomness;
    signal input pubKeyNullifierRandomness;

    signal output sigNullifier;
    signal output pubKeyNullifier;
    signal output pubKeyNullifierRandomnessHash;

    component ecdsa = BabyJubJubECDSA();
    ecdsa.Tx <== Tx;
    ecdsa.Ty <== Ty;
    ecdsa.Ux <== Ux;
    ecdsa.Uy <== Uy;
    ecdsa.s <== s;

    component pubKeyHash = Poseidon(2);
    pubKeyHash.inputs[0] <== ecdsa.pubKeyX;
    pubKeyHash.inputs[1] <== ecdsa.pubKeyY;

    component merkleProof = MerkleTreeInclusionProof(nLevels);
    merkleProof.leaf <== pubKeyHash.out;

    for (var i = 0; i < nLevels; i++) {
        merkleProof.pathIndices[i] <== pathIndices[i];
        merkleProof.siblings[i] <== siblings[i];
    }

    root === merkleProof.root;

    // sigNullifier = hash(s, sigNullifierRandomness)
    component sigNullifierHash = Poseidon(2);
    sigNullifierHash.inputs[0] <== s;
    sigNullifierHash.inputs[1] <== sigNullifierRandomness;

    // pubKeyNullifier = hash(s, pubKeyNullifierRandomness)
    component pubKeyNullifierHash = Poseidon(2);
    pubKeyNullifierHash.inputs[0] <== pubKeyHash.out;
    pubKeyNullifierHash.inputs[1] <== pubKeyNullifierRandomness;

    // pubKeyNullifierRandomnessHash = hash(pubKeyNullifierRandomness, pubKeyNullifierRandomness)
    component pubKeyNullifierRandomnessHasher = Poseidon(1);
    pubKeyNullifierRandomnessHasher.inputs[0] <== pubKeyNullifierRandomness;

    sigNullifier <== sigNullifierHash.out;
    pubKeyNullifier <== pubKeyNullifierHash.out;
    pubKeyNullifierRandomnessHash <== pubKeyNullifierRandomnessHasher.out;
}