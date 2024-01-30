pragma circom 2.1.2;

include "./pubkey_membership.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template FoldedPubkeyMembership(nLevels) {
    signal input step_in[4]; // [root, pubkey_nullifier_randomness, sig_nullifier_randomness, num_verified]
    signal output step_out[4]; // 

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

    // figure out how to accumulate these instead of sig nullifer but not worried about perfect accuracy now
    // signal output sigNullifier;
    // signal output pubKeyNullifier;
    // signal output pubKeyNullifierRandomnessHash;
    signal sigNullifier;
    signal pubKeyNullifier;
    signal pubKeyNullifierRandomnessHash;

    // label step_in values
    signal prev_root <== step_in[0];
    signal prev_pubkey_nullifier_randomness <== step_in[1];
    signal prev_sig_nullifier_randomness <== step_in[2];
    signal prev_num_verified <== step_in[3];

    // multiply step_in against eachother to prevent optimization out
    signal ensure_step_in_constrained <== prev_root * prev_num_verified;

    // check if root is 0 to determine if first step. ensure by verifying with first step root value being 0 when proving correctness of folding
    component is_first_step = IsZero();
    is_first_step.in <== prev_root;

    // multiplex root from previous step if not first step or from root pub input if first step
    component first_step_mux = MultiMux1(4);
    first_step_mux.c[0][0] <== prev_root;
    first_step_mux.c[0][1] <== root;
    first_step_mux.c[1][0] <== prev_pubkey_nullifier_randomness;
    first_step_mux.c[1][1] <== pubKeyNullifierRandomness;
    first_step_mux.c[2][0] <== prev_sig_nullifier_randomness;
    first_step_mux.c[2][1] <== sigNullifierRandomness;
    first_step_mux.c[3][0] <== prev_num_verified;
    first_step_mux.c[3][1] <== 0;
    first_step_mux.s <== is_first_step.out;

    // label mux outputs
    signal root_actual <== first_step_mux.out[0];
    signal pubkey_nullifier_randomness_actual <== first_step_mux.out[1];
    signal sig_nullifier_randomness_actual <== first_step_mux.out[2];
    signal num_verified_actual <== first_step_mux.out[3];

    // compute the membership witness for this step
    component membership = PubKeyMembership(nLevels);
    membership.s <== s;
    membership.root <== first_step_mux.out[0];
    membership.Tx <== Tx;
    membership.Ty <== Ty;
    membership.Ux <== Ux;
    membership.Uy <== Uy;
    membership.pathIndices <== pathIndices;
    membership.siblings <== siblings;
    membership.sigNullifierRandomness <== sig_nullifier_randomness_actual;
    membership.pubKeyNullifierRandomness <== pubkey_nullifier_randomness_actual;

    sigNullifier <== membership.sigNullifier;
    pubKeyNullifier <== membership.pubKeyNullifier;
    pubKeyNullifierRandomnessHash <== membership.pubKeyNullifierRandomnessHash;

    // pass output
    step_out[0] <== root_actual;
    step_out[1] <== pubkey_nullifier_randomness_actual;
    step_out[2] <== sig_nullifier_randomness_actual;
    step_out[3] <== num_verified_actual + 1;
}

component main { public[ step_in ]} = FoldedPubkeyMembership(8);