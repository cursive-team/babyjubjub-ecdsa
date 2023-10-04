const BN = require("bn.js");
import { buildPoseidon } from "circomlibjs";
import { EdwardsPoint, WeierstrassPoint, babyjubjub } from "./babyJubjub";
import { Signature, MerkleProof } from "./types";
import {
  hashEdwardsPublicKey,
  hexToBigInt,
  publicKeyFromString,
} from "./utils";

export const generateMerkleProof = async (
  pubKeys: string[],
  index: number
): Promise<MerkleProof> => {
  const TREE_DEPTH = 10;
  const DEFAULT_VALUE = BigInt(0);
  const poseidon = await buildPoseidon();

  const leaves = await Promise.all(
    pubKeys.map(async (pubKey) => {
      const pubKeyWeierstrass = publicKeyFromString(pubKey);
      const pubKeyEdwards = pubKeyWeierstrass.toEdwards();
      return await hashEdwardsPublicKey(pubKeyEdwards);
    })
  );

  // Todo: Cache zero values
  for (let i = pubKeys.length; i < 2 ** TREE_DEPTH; i++) {
    leaves.push(DEFAULT_VALUE);
  }

  let prevLayer: bigint[] = leaves;
  let nextLayer: bigint[] = [];
  let pathIndices: number[] = [];
  let siblings: bigint[] = [];

  for (let i = 0; i < TREE_DEPTH; i++) {
    pathIndices.push(index % 2);
    const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
    siblings.push(prevLayer[siblingIndex]);
    index = Math.floor(index / 2);

    for (let j = 0; j < prevLayer.length; j += 2) {
      const nextNode = poseidon([prevLayer[j], prevLayer[j + 1]]);
      nextLayer.push(hexToBigInt(poseidon.F.toString(nextNode, 16)));
    }

    prevLayer = nextLayer;
    nextLayer = [];
  }

  const root = prevLayer[0];

  return { root, pathIndices, siblings: siblings };
};

export const getPublicInputsFromSignature = (
  sig: Signature,
  msgHash: bigint,
  pubKey: WeierstrassPoint
): { T: EdwardsPoint; U: EdwardsPoint } => {
  const Fb = babyjubjub.Fb;
  const Fs = babyjubjub.Fs;

  for (const i of Array(babyjubjub.cofactor).keys()) {
    // Todo: Use v value from signature
    for (const parity of [0, 1]) {
      const r = Fb.add(sig.r, Fb.mul(BigInt(i), Fs.p));
      const rInv = Fs.inv(r);
      let R;
      try {
        R = babyjubjub.ec.curve.pointFromX(new BN(r.toString(16), 16), parity);
      } catch (e) {
        continue;
      }
      const rawT = R.mul(rInv.toString(16));
      const T = WeierstrassPoint.fromEllipticPoint(rawT);
      const G = babyjubjub.ec.curve.g;
      const rInvm = Fs.neg(Fs.mul(rInv, msgHash));
      const rawU = G.mul(rInvm.toString(16));
      const U = WeierstrassPoint.fromEllipticPoint(rawU);
      const sT = rawT.mul(sig.s.toString(16));
      const rawsTU = sT.add(rawU);
      const sTU = WeierstrassPoint.fromEllipticPoint(rawsTU);

      if (sTU.equals(pubKey)) {
        return { T: T.toEdwards(), U: U.toEdwards() };
      }
    }
  }

  throw new Error("Could not find valid public inputs");
};
