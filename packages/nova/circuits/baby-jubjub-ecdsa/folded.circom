pragma circom 2.1.2;

include "./pubkey_membership.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template FoldedPubkeyMembership(depth, batchSize) {
    signal input step_in[4]; // [root, pubkey_nullifier_randomness, sig_nullifier_randomness, num_verified]
    signal output step_out[4];

    signal input s;
    signal input Tx; 
    signal input Ty; 
    signal input Ux;
    signal input Uy;
    signal input pathIndices[nLevels];
    signal input siblings[nLevels];
    signal input sigNullifierRandomness;
    signal input pubKeyNullifierRandomness;
    signal input chaff; // set 0 if not chaff, 1 if chaff

    // figure out how to accumulate these instead of sig nullifer but not worried about perfect accuracy now
    // signal output sigNullifier;
    // signal output pubKeyNullifier;
    // signal output pubKeyNullifierRandomnessHash;
    signal sigNullifier;
    signal pubKeyNullifier;
    signal pubKeyNullifierRandomnessHash;

    // check that chaff is 0 or 1
    signal chaffBooleanConstraint <== chaff * (1 - chaff);
    component chaffIsBoolean = IsZero();
    chaffIsBoolean.in <== chaffBooleanConstraint;

    // component memberships[batchSize];
    // for (var i = 0; i < batchSize; i++) {
    //     memberships[i] = PubKeyMembership(depth);
    //     membership.s <== s;
    // membership.root <== step_in[0];
    // membership.Tx <== Tx;
    // membership.Ty <== Ty;
    // membership.Ux <== Ux;
    // membership.Uy <== Uy;
    // membership.pathIndices <== pathIndices;
    // membership.siblings <== siblings;
    // membership.sigNullifierRandomness <== step_in[2];
    // membership.pubKeyNullifierRandomness <== step_in[1];
    // membership.chaff <== chaff;
    // }

    // compute the membership witness for this step
    component membership = PubKeyMembership(nLevels);
    membership.s <== s;
    membership.root <== step_in[0];
    membership.Tx <== Tx;
    membership.Ty <== Ty;
    membership.Ux <== Ux;
    membership.Uy <== Uy;
    membership.pathIndices <== pathIndices;
    membership.siblings <== siblings;
    membership.sigNullifierRandomness <== step_in[2];
    membership.pubKeyNullifierRandomness <== step_in[1];
    membership.chaff <== chaff;

    // mux incresing num verified if membership is true
    component verified = Mux1();
    mux.a <== step_in[3] + 1;
    mux.b <== step_in[3];

    // pass output
    step_out[0] <== step_in[0];
    step_out[1] <== pubkeyNullifierRandomness;
    step_out[2] <== sigNullifierRandomness;
    step_out[3] <== verified.out;
}

component main { public[ step_in ]} = FoldedPubkeyMembership(8);