const snarkjs = require("snarkjs");
const fs = require("fs");
import {
  MerkleProof,
  IncrementalMerkleTree,
} from "@zk-kit/incremental-merkle-tree";
import { buildPoseidon } from "circomlibjs";
import { Signature, ZKP, MembershipProofInputs } from "./types";
import { getPublicInputsFromSignature } from "./witness";
import { hashMessage } from "./sig";
import { WeierstrassPoint } from "./babyJubjub";

export const proveMembership = async (
  sig: Signature,
  pubKey: WeierstrassPoint,
  msg: string,
  merkleProof: MerkleProof
): Promise<ZKP> => {
  const { T, U } = getPublicInputsFromSignature(sig, msg, pubKey);
  const proofInputs: MembershipProofInputs = {
    s: sig.s,
    Tx: T.x,
    Ty: T.y,
    Ux: U.x,
    Uy: U.y,
    root: merkleProof.root,
    pathIndices: merkleProof.pathIndices,
    siblings: merkleProof.siblings,
  };

  return await snarkjs.groth16.fullProve(
    proofInputs,
    "circuit.wasm",
    "circuit.zkey"
  );
};

export const verifyMembership = async (zkProof: ZKP): Promise<boolean> => {
  const { proof, publicSignals } = zkProof;

  const vKey = JSON.parse(fs.readFileSync("verification_key.json"));

  return await snarkjs.groth16.verify(vKey, publicSignals, proof);
};

export const generateMerkleProof = async (
  pubKeys: string[],
  index: number
): Promise<MerkleProof> => {
  const poseidon = await buildPoseidon();

  pubKeys.forEach((pubKey) => {
    return hashMessage(pubKey);
  });

  const tree = new IncrementalMerkleTree(poseidon, 10, BigInt(0), 2, pubKeys);

  return tree.createProof(index);
};
