pragma circom 2.1.2;

include "./templates/pubkey_membership.circom";
include "./node_modules/circomlib/circuits/mux1.circom";
include "./node_modules/circomlib/circuits/comparators.circom";

template FoldedPubkeyMembership(depth, batchSize) {
    signal input step_in[2]; // [root, num_verified]
    signal output step_out[2];

    signal input s[batchSize];
    signal input Tx[batchSize]; 
    signal input Ty[batchSize]; 
    signal input Ux[batchSize];
    signal input Uy[batchSize];
    signal input pathIndices[batchSize][depth];
    signal input siblings[batchSize][depth];
    signal input active[batchSize]; // set 0 if not chaff, 1 if chaff

    // loop for batch size and verify each membership
    component memberships[batchSize];
    component activeBoolChecks[batchSize];
    component incrementMux[batchSize];
    signal activeBoolConstraints[batchSize];
    signal numVerified[batchSize + 1];
    numVerified[0] <== step_in[1];
    for (var i = 0; i < batchSize; i++) {
        // check if chaff is boolean
        activeBoolConstraints[i] <== active[i] * (1 - active[i]);
        activeBoolChecks[i] = IsZero();
        activeBoolChecks[i].in <== activeBoolConstraints[i];

        // verify membership
        memberships[i] = PubKeyMembership(depth);
        memberships[i].s <== s[i];
        memberships[i].root <== step_in[0];
        memberships[i].Tx <== Tx[i];
        memberships[i].Ty <== Ty[i];
        memberships[i].Ux <== Ux[i];
        memberships[i].Uy <== Uy[i];
        memberships[i].pathIndices <== pathIndices[i];
        memberships[i].siblings <== siblings[i];
        memberships[i].active <== active[i];

        // increment verified if chaff is false
        incrementMux[i] = Mux1();
        incrementMux[i].c[0] <== numVerified[i] + 1;
        incrementMux[i].c[1] <== numVerified[i];
        incrementMux[i].s <== active[i];
        numVerified[i + 1] <== incrementMux[i].out;
    }

    // pass output
    step_out[0] <== step_in[0];
    step_out[1] <== numVerified[batchSize];
}

component main { public[ step_in ]} = FoldedPubkeyMembership(9, 1);