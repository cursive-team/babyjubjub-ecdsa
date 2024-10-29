pragma circom 2.1.2;

include "./baby_jubjub_ecdsa.circom";
include "./tree.circom";
include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "../../../node_modules/circomlib/circuits/eddsaposeidon.circom";

template ValidTap() {
    // Actual tap efficient ECDSA signature
    signal input tapS;
    signal input tapTx; 
    signal input tapTy; 
    signal input tapUx;
    signal input tapUy;

    // Randomness for nullifiers
    signal input sigNullifierRandomness;
    signal input pubKeyNullifierRandomness;

    // EdDSA signature on tap public key from Cursive
    signal input pubKeySignatureR8x;
    signal input pubKeySignatureR8y;
    signal input pubKeySignatureS;

    // Cursive EdDSA public key for verification
    signal input cursivePubKeyAx;
    signal input cursivePubKeyAy;

    // Nullifiers on signature and pubkey
    signal output sigNullifier;
    signal output pubKeyNullifier;
    signal output pubKeyNullifierRandomnessHash;

    // Verify tap signature
    var tapPubKeyX, tapPubKeyY;
    (tapPubKeyX, tapPubKeyY) = BabyJubJubECDSA()(
      tapS,
      tapTx,
      tapTy,
      tapUx,
      tapUy
    );

    // Extract public key from tap signature
    signal tapPubKeyHash;
    tapPubKeyHash <== Poseidon(2)(
      [tapPubKeyX, tapPubKeyY]
    );

    // Verify EdDSA signature on tap public key
    EdDSAPoseidonVerifier()(
        1,
        cursivePubKeyAx,
        cursivePubKeyAy,
        pubKeySignatureS,
        pubKeySignatureR8x,
        pubKeySignatureR8y,
        tapPubKeyHash
    );

    // sigNullifier = hash(s, sigNullifierRandomness)
    sigNullifier <== Poseidon(2)([tapS, sigNullifierRandomness]);

    // pubKeyNullifier = hash(s, pubKeyNullifierRandomness)
    pubKeyNullifier <== Poseidon(2)([tapPubKeyHash, pubKeyNullifierRandomness]);

    // pubKeyNullifierRandomnessHash = hash(pubKeyNullifierRandomness)
    pubKeyNullifierRandomnessHash <== Poseidon(1)([pubKeyNullifierRandomness]);
}