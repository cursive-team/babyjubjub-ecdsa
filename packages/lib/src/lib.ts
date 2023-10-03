const snarkjs = require("snarkjs");
const fs = require("fs");
import { IncrementalMerkleTree } from "@zk-kit/incremental-merkle-tree";
import { buildPoseidon } from "circomlibjs";
import { Signature, ZKP, MembershipProofInputs, MerkleProof } from "./types";
import { getPublicInputsFromSignature } from "./witness";
import {
  bytesToBigInt,
  bytesToHex,
  hashEdwardsPublicKey,
  hashMessage,
  hashPublicKey,
  hexToBigInt,
  hexToBytes,
  publicKeyFromString,
} from "./sig";

export const proveMembership = async (
  sig: Signature,
  pubKeys: string[],
  index: number,
  msg: string
): Promise<ZKP> => {
  const pubKey = publicKeyFromString(pubKeys[index]);

  // Todo: Recover public key from signature, remove index
  const { T, U } = getPublicInputsFromSignature(sig, msg, pubKey);

  const merkleProof = await generateMerkleProof(pubKeys, index);

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

  console.log(proofInputs);

  return await snarkjs.groth16.fullProve(
    proofInputs,
    __dirname + "/circuits/membership.wasm",
    __dirname + "/circuits/membership.zkey"
  );
};

export const verifyMembership = async (zkProof: ZKP): Promise<boolean> => {
  const { proof, publicSignals } = zkProof;

  const vKey = JSON.parse(
    fs.readFileSync(__dirname + "/circuits/membership_vkey.json")
  );

  return await snarkjs.groth16.verify(vKey, publicSignals, proof);
};

export const generateMerkleProof = async (
  pubKeys: string[],
  index: number
): Promise<MerkleProof> => {
  const poseidon = await buildPoseidon();
  const hashedPubKeys = await Promise.all(
    pubKeys.map((pubKey) => {
      const pubKeyWeierstrass = publicKeyFromString(pubKey);
      const pubKeyEdwards = pubKeyWeierstrass.toEdwards();
      return hashEdwardsPublicKey(pubKeyEdwards);
    })
  );

  const tree = new IncrementalMerkleTree(
    poseidon,
    10,
    BigInt(0),
    2,
    hashedPubKeys
  );

  const proof = tree.createProof(index);

  const root = bytesToBigInt(proof.root);
  const siblings = proof.siblings.map((siblingArray) => {
    const sibling = siblingArray[0];
    if (typeof sibling === "bigint") {
      return sibling;
    }
    return bytesToBigInt(sibling);
  });

  return {
    root,
    pathIndices: proof.pathIndices,
    siblings,
  };
};
