const snarkjs = require("snarkjs");
import {
  Signature,
  ZKP,
  MembershipZKPInputs,
  EcdsaMembershipProof,
} from "./types";
import { getPublicInputsFromSignature, generateMerkleProof } from "./inputGen";
import { isNode } from "./utils";
import { WeierstrassPoint } from "./babyJubjub";

export const proveMembership = async (
  sig: Signature,
  pubKeys: WeierstrassPoint[],
  index: number,
  msgHash: bigint,
  nullifierRandomness: bigint = BigInt(0),
  pathToCircuits: string | undefined = undefined,
  hashFn: any | undefined = undefined
): Promise<EcdsaMembershipProof> => {
  console.time("Membership Proof Generation");
  console.time("T and U Generation");
  const pubKey = pubKeys[index];
  const { R, T, U } = getPublicInputsFromSignature(sig, msgHash, pubKey);
  console.timeEnd("T and U Generation");

  console.time("Merkle Proof Generation");
  const edwardsPubKeys = await Promise.all(
    pubKeys.map(async (pubKey) => pubKey.toEdwards())
  );
  const merkleProof = await generateMerkleProof(edwardsPubKeys, index, hashFn);
  console.timeEnd("Merkle Proof Generation");

  console.time("ZK Proof Generation");
  const proofInputs: MembershipZKPInputs = {
    s: sig.s,
    Tx: T.x,
    Ty: T.y,
    Ux: U.x,
    Uy: U.y,
    root: merkleProof.root,
    pathIndices: merkleProof.pathIndices,
    siblings: merkleProof.siblings,
    nullifierRandomness,
  };
  const zkp = await generateMembershipZKP(proofInputs, pathToCircuits);
  console.timeEnd("ZK Proof Generation");

  // @ts-ignore
  await globalThis.curve_bn128.terminate();
  console.timeEnd("Membership Proof Generation");

  return {
    R,
    msgHash,
    T,
    U,
    zkp,
  };
};

export const batchProveMembership = async (
  sigs: Signature[],
  pubKeys: WeierstrassPoint[],
  indexes: number[],
  msgHashes: bigint[],
  nullifierRandomness: bigint = BigInt(0),
  pathToCircuits: string | undefined = undefined,
  hashFn: any | undefined = undefined
): Promise<EcdsaMembershipProof[]> => {
  const numProofs = sigs.length;
  if (numProofs !== indexes.length || numProofs !== msgHashes.length) {
    throw new Error(
      "Must provide the same number of signatures, indexes, and message hashes!"
    );
  }

  console.time("Batch Membership Proof Generation");
  const edwardsPubKeys = pubKeys.map((pubKey) => pubKey.toEdwards());

  const proofs = await Promise.all(
    sigs.map(async (sig, i) => {
      console.time(`Membership Proof Generation: ${i}`);
      const index = indexes[i];
      const msgHash = msgHashes[i];

      console.time(`T and U Generation: ${i}`);
      const pubKey = pubKeys[index];
      const { R, T, U } = getPublicInputsFromSignature(sig, msgHash, pubKey);
      console.timeEnd(`T and U Generation: ${i}`);

      console.time(`Merkle Proof Generation: ${i}`);
      const merkleProof = await generateMerkleProof(
        edwardsPubKeys,
        index,
        hashFn
      );
      console.timeEnd(`Merkle Proof Generation: ${i}`);

      console.time(`ZK Proof Generation: ${i}`);
      const proofInputs: MembershipZKPInputs = {
        s: sig.s,
        Tx: T.x,
        Ty: T.y,
        Ux: U.x,
        Uy: U.y,
        root: merkleProof.root,
        pathIndices: merkleProof.pathIndices,
        siblings: merkleProof.siblings,
        nullifierRandomness,
      };
      const zkp = await generateMembershipZKP(proofInputs, pathToCircuits);
      console.timeEnd(`ZK Proof Generation: ${i}`);
      console.timeEnd(`Membership Proof Generation: ${i}`);

      return {
        R,
        msgHash,
        T,
        U,
        zkp,
      };
    })
  );

  // @ts-ignore
  await globalThis.curve_bn128.terminate();
  console.timeEnd("Batch Membership Proof Generation");

  return proofs;
};

export const generateMembershipZKP = async (
  proofInputs: MembershipZKPInputs,
  pathToCircuits: string | undefined = undefined
): Promise<ZKP> => {
  if (isNode() && pathToCircuits === undefined) {
    throw new Error(
      "Path to circuits must be provided for server side proving!"
    );
  }

  const wasmPath = isNode()
    ? pathToCircuits + "pubkey_membership.wasm"
    : "https://storage.googleapis.com/jubmoji-circuits/pubkey_membership.wasm";
  const zkeyPath = isNode()
    ? pathToCircuits + "pubkey_membership.zkey"
    : "https://storage.googleapis.com/jubmoji-circuits/pubkey_membership.zkey";

  const proof = await snarkjs.groth16.fullProve(
    proofInputs,
    wasmPath,
    zkeyPath
  );

  return proof;
};
