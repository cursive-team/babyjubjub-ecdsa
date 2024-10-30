// @ts-ignore
import { buildPoseidonReference as buildPoseidon } from "circomlibjs";
import {
  hashEdwardsPublicKey,
  hexToBigInt,
  publicKeyFromString,
} from "../../lib/src/utils";
import { signMessage, derivePublicKey } from "@zk-kit/eddsa-poseidon";
const snarkjs = require("snarkjs");
import fs from "fs";
import { getPublicInputsFromSignature } from "../src/inputGen";

describe("ValidTap circuit", () => {
  const pathToCircuits = process.cwd() + "/test/circuits/";

  afterAll(async () => {
    // snarkjs will not terminate this object automatically
    // We should do so after all proving/verification is finished for caching purposes
    // See: https://github.com/iden3/snarkjs/issues/152
    // @ts-ignore
    await globalThis.curve_bn128.terminate();
  });

  test("should verify a valid tap with EdDSA signature", async () => {
    // build poseidon
    const poseidon = await buildPoseidon();

    // setup valid ECDSA signature
    const msgHash = BigInt("0");
    const sig = {
      r: hexToBigInt(
        "00EF7145470CEC0B683C629CBA8ED58110000FFE657366F7D5A91F2D149DD8B5"
      ),
      s: hexToBigInt(
        "0370C60A23266F520C56DA088B4C4AFAAAF6BB1993A501980F6D8FB6F343984A"
      ),
    };
    const tapPubKey = publicKeyFromString(
      "041052d6da0c3d7248e39e08912e2daa53c4e54cd9f2d96e3702fa15e77b199a501cd835bbddcc77134dc59dbbde2aa702183a68c90877906a31536eef972fac36"
    );

    // convert to Efficient ECDSA format
    let { R, T, U } = getPublicInputsFromSignature(sig, msgHash, tapPubKey);
    let edwardsTapPubKey = tapPubKey.toEdwards();
    let tapPubKeyHash = await hashEdwardsPublicKey(edwardsTapPubKey, poseidon);

    // Generate Cursive EdDSA key pair
    const cursivePrivKey = Buffer.from(
      "0001020304050607080900010203040506070809000102030405060708090001",
      "hex"
    );
    const cursivePubKey = await derivePublicKey(cursivePrivKey);
    const cursivePubKeyAx = cursivePubKey[0];
    const cursivePubKeyAy = cursivePubKey[1];

    // Generate nullifier randomness
    const sigNullifierRandomness = BigInt("420420420");
    const pubKeyNullifierRandomness = BigInt("13371337");

    // Generate Cursive EdDSA signature on tap public key
    const signature = signMessage(cursivePrivKey, tapPubKeyHash);
    const pubKeySignatureR8x = signature.R8[0];
    const pubKeySignatureR8y = signature.R8[1];
    const pubKeySignatureS = signature.S;

    // Create circuit input
    const input = {
      tapS: sig.s,
      tapTx: T.x,
      tapTy: T.y,
      tapUx: U.x,
      tapUy: U.y,
      sigNullifierRandomness,
      pubKeyNullifierRandomness,
      pubKeySignatureR8x,
      pubKeySignatureR8y,
      pubKeySignatureS,
      cursivePubKeyAx,
      cursivePubKeyAy,
    };

    // Expected nullifier outputs
    const expectedSigNullifier = hexToBigInt(
      poseidon.F.toString(poseidon([sig.s, sigNullifierRandomness]), 16)
    );
    const expectedPubKeyNullifier = hexToBigInt(
      poseidon.F.toString(
        poseidon([tapPubKeyHash, pubKeyNullifierRandomness]),
        16
      )
    );
    const expectedPubKeyNullifierRandomnessHash = hexToBigInt(
      poseidon.F.toString(poseidon([pubKeyNullifierRandomness]), 16)
    );

    // Generate and verify proof
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      pathToCircuits + "valid_tap.wasm",
      pathToCircuits + "valid_tap.zkey"
    );

    const vKey = JSON.parse(
      fs.readFileSync(pathToCircuits + "valid_tap_vkey.json").toString()
    );
    const verified = await snarkjs.groth16.verify(vKey, publicSignals, proof);

    expect(verified).toBe(true);
    expect(publicSignals[0]).toBe(expectedSigNullifier.toString());
    expect(publicSignals[1]).toBe(expectedPubKeyNullifier.toString());
    expect(publicSignals[2]).toBe(
      expectedPubKeyNullifierRandomnessHash.toString()
    );
  });
});
