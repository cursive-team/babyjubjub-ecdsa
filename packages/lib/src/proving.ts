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
  const wasmPath = isNode()
    ? circuitsPath + "pubkey_membership.wasm"
    : "https://storage.googleapis.com/jubmoji-circuits/pubkey_membership.wasm";
  const zkeyPath = isNode()
    ? circuitsPath + "pubkey_membership.zkey"
    : "https://storage.googleapis.com/jubmoji-circuits/pubkey_membership.zkey";
  const proof = await snarkjs.groth16.fullProve(
    proofInputs,
    wasmPath,
    zkeyPath
  );

  console.timeEnd("Proving");

  return proof;
};

export const verifyMembership = async (zkProof: ZKP): Promise<boolean> => {
  console.time("Verification");

  const { proof, publicSignals } = zkProof;

  const vKey = isNode()
    ? await getVerificationKeyFromFile()
    : await getVerificationKeyFromUrl();

  const verified = await snarkjs.groth16.verify(vKey, publicSignals, proof);

  console.timeEnd("Verification");

  return verified;
};

const getVerificationKeyFromFile = async (): Promise<any> => {
  const vKey = JSON.parse(
    fs.readFileSync(getPathToCircuits() + "pubkey_membership_vkey.json")
  );
  return vKey;
};

const getVerificationKeyFromUrl = async (): Promise<any> => {
  const response = await fetch(
    "https://storage.googleapis.com/jubmoji-circuits/pubkey_membership_vkey.json"
  );
  const vKey = await response.json();
  return vKey;
};

export const getPathToCircuits = (): string => {
  return isNode() ? __dirname + "/circuits/" : "";
};

export const isNode = (): boolean => {
  return typeof window === "undefined";
};
