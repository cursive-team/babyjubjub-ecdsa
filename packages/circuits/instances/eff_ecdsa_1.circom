pragma circom 2.1.2;

include "../spartan-ecdsa-circuits/eff_ecdsa.circom";

component main { public[ Tx, Ty, Ux, Uy ]} = EfficientECDSA();