const BN = require("bn.js");
// @ts-ignore
import { buildPoseidonReference } from "circomlibjs";
import { EdwardsPoint, WeierstrassPoint, babyjubjub } from "./babyJubjub";
import { Signature, MerkleProof } from "./types";
import { hashEdwardsPublicKey, hexToBigInt } from "./utils";

export const computeMerkleRoot = async (
  pubKeys: EdwardsPoint[],
  hashFn: any | undefined = undefined
): Promise<bigint> => {
  const proof = await generateMerkleProof(pubKeys, 0, hashFn);
  return proof.root;
};

export const generateMerkleProof = async (
  pubKeys: EdwardsPoint[],
  index: number,
  hashFn: any | undefined = undefined
): Promise<MerkleProof> => {
  const TREE_DEPTH = 8;
  const ZEROS = [
    "0",
    "14744269619966411208579211824598458697587494354926760081771325075741142829156",
    "7423237065226347324353380772367382631490014989348495481811164164159255474657",
    "11286972368698509976183087595462810875513684078608517520839298933882497716792",
    "3607627140608796879659380071776844901612302623152076817094415224584923813162",
    "19712377064642672829441595136074946683621277828620209496774504837737984048981",
    "20775607673010627194014556968476266066927294572720319469184847051418138353016",
    "3396914609616007258851405644437304192397291162432396347162513310381425243293",
  ];
  const poseidon =
    hashFn === undefined ? await buildPoseidonReference() : hashFn;

  const leaves = await Promise.all(pubKeys.map(hashEdwardsPublicKey));

  let prevLayer: bigint[] = leaves;
  let nextLayer: bigint[] = [];
  let pathIndices: number[] = [];
  let siblings: bigint[] = [];

  for (let i = 0; i < TREE_DEPTH; i++) {
    pathIndices.push(index % 2);
    const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
    const sibling =
      siblingIndex === prevLayer.length
        ? BigInt(ZEROS[i])
        : prevLayer[siblingIndex];
    siblings.push(sibling);
    index = Math.floor(index / 2);

    for (let j = 0; j < prevLayer.length; j += 2) {
      const secondNode =
        j + 1 === prevLayer.length ? BigInt(ZEROS[i]) : prevLayer[j + 1];
      const nextNode = poseidon([prevLayer[j], secondNode]);
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
): { R: EdwardsPoint; T: EdwardsPoint; U: EdwardsPoint } => {
  const Fb = babyjubjub.Fb;
  const Fs = babyjubjub.Fs;

  for (let i = 0; i < babyjubjub.cofactor; i++) {
    for (const parity of [0, 1]) {
      const r = Fb.add(sig.r, Fb.mul(BigInt(i), Fs.p));
      const rInv = Fs.inv(r);
      let rawR;
      try {
        rawR = babyjubjub.ec.curve.pointFromX(
          new BN(r.toString(16), 16),
          parity
        );
      } catch (e) {
        continue;
      }
      const rawT = rawR.mul(rInv.toString(16));
      const T = WeierstrassPoint.fromEllipticPoint(rawT);
      const G = babyjubjub.ec.curve.g;
      const rInvm = Fs.neg(Fs.mul(rInv, msgHash));
      const rawU = G.mul(rInvm.toString(16));
      const U = WeierstrassPoint.fromEllipticPoint(rawU);
      const sT = rawT.mul(sig.s.toString(16));
      const rawsTU = sT.add(rawU);
      const sTU = WeierstrassPoint.fromEllipticPoint(rawsTU);

      if (sTU.equals(pubKey)) {
        const R = WeierstrassPoint.fromEllipticPoint(rawR);
        return { R: R.toEdwards(), T: T.toEdwards(), U: U.toEdwards() };
      }
    }
  }

  throw new Error("Could not find valid public inputs");
};
