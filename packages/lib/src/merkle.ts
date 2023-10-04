import { buildPoseidon } from "circomlibjs";
import { MerkleProof } from "./types";
import { hashEdwardsPublicKey, hexToBigInt, publicKeyFromString } from "./sig";

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
