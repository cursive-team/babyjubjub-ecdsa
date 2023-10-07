pragma circom 2.1.2;

include "../baby-jubjub-ecdsa/pubkey_membership.circom";

component main { public[ root, Tx, Ty, Ux, Uy, nullifierRandomness ]} = PubKeyMembership(8);