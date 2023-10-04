const snarkjs = require("snarkjs");
const fs = require("fs");
import { Signature, ZKP, MembershipProofInputs } from "./types";
import { getPublicInputsFromSignature, generateMerkleProof } from "./inputGen";
import { publicKeyFromString } from "./utils";

export const proveMembership = async (
  sig: Signature,
  pubKeys: string[],
  index: number,
  msgHash: bigint
): Promise<ZKP> => {
  console.time("T and U Generation");

  const pubKey = publicKeyFromString(pubKeys[index]);

  const { T, U } = getPublicInputsFromSignature(sig, msgHash, pubKey);

  console.timeEnd("T and U Generation");

  console.time("Merkle Proof Generation");

  const merkleProof = await generateMerkleProof(pubKeys, index);

  console.timeEnd("Merkle Proof Generation");

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

  console.time("Proving");

  const circuitsPath = getPathToCircuits();
  const proof = await snarkjs.groth16.fullProve(
    proofInputs,
    circuitsPath + "pubkey_membership.wasm",
    circuitsPath + "pubkey_membership.zkey"
  );

  console.timeEnd("Proving");

  return proof;
};

export const verifyMembership = async (zkProof: ZKP): Promise<boolean> => {
  console.time("Verification");

  const { proof, publicSignals } = zkProof;

  const vKey = JSON.parse(
    fs.readFileSync(getPathToCircuits() + "pubkey_membership_vkey.json")
  );

  const verified = await snarkjs.groth16.verify(vKey, publicSignals, proof);

  console.timeEnd("Verification");

  return verified;
};

export const getPathToCircuits = (): string => {
  const isNode = typeof window === "undefined";

  return isNode ? __dirname + "/circuits/" : "";
};
