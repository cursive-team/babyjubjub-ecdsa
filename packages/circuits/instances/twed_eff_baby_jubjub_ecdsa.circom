pragma circom 2.1.2;

include "../baby-jubjub-ecdsa/twed_eff_ecdsa.circom";

component main { public[ Tx, Ty, Ux, Uy ]} = EfficientECDSA();