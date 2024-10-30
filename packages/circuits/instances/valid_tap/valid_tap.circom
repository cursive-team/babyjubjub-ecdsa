pragma circom 2.1.2;

include "../baby-jubjub-ecdsa/valid_tap.circom";

component main { public[ sigNullifierRandomness, cursivePubKeyAx, cursivePubKeyAy, tapTx, tapTy, tapUx, tapUy ]} = ValidTap();