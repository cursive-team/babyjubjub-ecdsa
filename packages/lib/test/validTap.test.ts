// @ts-ignore
import { hexToBigInt, publicKeyFromString } from "../../lib/src/utils";
import { getPublicInputsFromSignature } from "../src/inputGen";
import { signMessage, derivePublicKey } from "@zk-kit/eddsa-poseidon";
import { poseidon1, poseidon2 } from "poseidon-lite";
const snarkjs = require("snarkjs");
import fs from "fs";

const timer = (fn: Function) => {
  return async (...args: any[]) => {
    const start = performance.now();
    const result = await fn(...args);
    const end = performance.now();
    console.log(`${fn.name} took ${end - start} milliseconds.`);
    return result;
  };
};

describe("ValidTap circuit", () => {
  const pathToCircuits = process.cwd() + "/test/circuits/";

  afterAll(async () => {
    // snarkjs will not terminate this object automatically
    // We should do so after all proving/verification is finished for caching purposes
    // See: https://github.com/iden3/snarkjs/issues/152
    // @ts-ignore
    if (globalThis.curve_bn128) {
      // @ts-ignore
      await globalThis.curve_bn128.terminate();
    }
  });

  test("generate EdDSA signature of tap public key", async () => {
    const tapPubKey = await publicKeyFromString(
      "041052d6da0c3d7248e39e08912e2daa53c4e54cd9f2d96e3702fa15e77b199a501cd835bbddcc77134dc59dbbde2aa702183a68c90877906a31536eef972fac36"
    );
    let edwardsTapPubKey = tapPubKey.toEdwards();
    let poseidonTapPubKeyHash = await poseidon2([
      edwardsTapPubKey.x,
      edwardsTapPubKey.y,
    ]);

    // Generate Cursive EdDSA key pair
    const cursivePrivKey = Buffer.from(
      "0001020304050607080900010203040506070809000102030405060708090001",
      "hex"
    );
    const cursivePubKey = await derivePublicKey(cursivePrivKey);
    const cursivePubKeyAx = cursivePubKey[0];
    const cursivePubKeyAy = cursivePubKey[1];

    // Generate Cursive EdDSA signature on tap public key
    const signature = await signMessage(cursivePrivKey, poseidonTapPubKeyHash);
    const pubKeySignatureR8x = signature.R8[0];
    const pubKeySignatureR8y = signature.R8[1];
    const pubKeySignatureS = signature.S;
  });

  test("should verify a valid tap with EdDSA signature", async () => {
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

    // Generate nullifier randomness
    const sigNullifierRandomness = BigInt("420420420");
    const pubKeyNullifierRandomness = BigInt("13371337");

    const tapPubKey = await publicKeyFromString(
      "041052d6da0c3d7248e39e08912e2daa53c4e54cd9f2d96e3702fa15e77b199a501cd835bbddcc77134dc59dbbde2aa702183a68c90877906a31536eef972fac36"
    );
    let edwardsTapPubKey = tapPubKey.toEdwards();
    let poseidonTapPubKeyHash = await poseidon2([
      edwardsTapPubKey.x,
      edwardsTapPubKey.y,
    ]);

    // Generate Cursive EdDSA key pair
    const cursivePrivKey = Buffer.from(
      "0001020304050607080900010203040506070809000102030405060708090001",
      "hex"
    );
    const cursivePubKey = await derivePublicKey(cursivePrivKey);
    const cursivePubKeyAx = cursivePubKey[0];
    const cursivePubKeyAy = cursivePubKey[1];

    // Generate Cursive EdDSA signature on tap public key
    const signature = await signMessage(cursivePrivKey, poseidonTapPubKeyHash);
    const pubKeySignatureR8x = signature.R8[0];
    const pubKeySignatureR8y = signature.R8[1];
    const pubKeySignatureS = signature.S;

    // convert to Efficient ECDSA format
    let { R, T, U } = await timer(getPublicInputsFromSignature)(
      sig,
      msgHash,
      tapPubKey
    );

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
    const expectedSigNullifier = await timer(poseidon2)([
      sig.s,
      sigNullifierRandomness,
    ]);
    const expectedPubKeyNullifier = await timer(poseidon2)([
      poseidonTapPubKeyHash,
      pubKeyNullifierRandomness,
    ]);
    const expectedPubKeyNullifierRandomnessHash = await timer(poseidon1)([
      pubKeyNullifierRandomness,
    ]);

    // Generate and verify proof
    const wtns = {
      type: "mem",
    };
    await timer(snarkjs.wtns.calculate)(
      input,
      pathToCircuits + "valid_tap.wasm",
      wtns
    );
    const { proof, publicSignals } = await timer(snarkjs.groth16.prove)(
      pathToCircuits + "valid_tap.zkey",
      wtns
    );

    const vKey = JSON.parse(
      fs.readFileSync(pathToCircuits + "valid_tap_vkey.json").toString()
    );
    const verified = await timer(snarkjs.groth16.verify)(
      vKey,
      publicSignals,
      proof
    );

    expect(verified).toBe(true);
    expect(publicSignals[0]).toBe(expectedSigNullifier.toString());
    expect(publicSignals[1]).toBe(expectedPubKeyNullifier.toString());
    expect(publicSignals[2]).toBe(
      expectedPubKeyNullifierRandomnessHash.toString()
    );
    expect(publicSignals[8]).toBe(cursivePubKeyAx.toString());
    expect(publicSignals[9]).toBe(cursivePubKeyAy.toString());
  });
});
