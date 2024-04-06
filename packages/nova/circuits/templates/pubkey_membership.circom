pragma circom 2.1.2;

include "./baby_jubjub_ecdsa.circom";
include "./tree.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

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
    signal input active;

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

    // mux the root of the merkle tree to see if membership check should be constrained
    component activeMux = Mux1();
    activeMux.c[0] <== merkleProof.root;
    activeMux.c[1] <== root;
    activeMux.s <== active;

    // check the root of the merkle tree if chaff is false
    root === activeMux.out;
}