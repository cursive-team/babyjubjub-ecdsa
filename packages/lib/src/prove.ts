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

/**
 * Generates an ECDSA membership proof for a given signature
 * Proof contains a ZKP as well as information needed for out of circuit verification
 * @param sig - The signature to generate the proof for
 * @param pubKeys - The list of public keys comprising the ZKP anonymity set
 * @param index - The index of the public key that generated the signature
 * @param msgHash - The hash of the message that was signed
 * @param nullifierRandomness - Optional nullifier randomness used to generate unique nullifiers
 * @param pathToCircuits - The path to the circuits directory. Only needed for server side proving
 * @param hashFn - The hash function to use for the merkle tree. Defaults to Poseidon
 * @returns - The membership proof
 */
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

  // snarkjs will not terminate this object automatically
  // We should do so after all proving/verification is finished for caching purposes
  // See: https://github.com/iden3/snarkjs/issues/152
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

/**
 * Generates ECDSA membership proofs for a list of signatures
 * Can only be used for the same list of public keys and fixed nullifier randomness
 * @param sigs - The list of signatures to generate proofs for
 * @param pubKeys - The list of public keys comprising the ZKP anonymity set
 * @param indexes - The list of indexes corresponding to the public keys that generated the signatures
 * @param msgHashes - The list of message hashes corresponding to the messages that were signed
 * @param nullifierRandomness - Optional nullifier randomness used to generate unique nullifiers
 * @param pathToCircuits - The path to the circuits directory. Only needed for server side proving
 * @param hashFn - The hash function to use for the merkle tree. Defaults to Poseidon
 * @returns - The list of membership proofs
 */
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

  // snarkjs will not terminate this object automatically
  // We should do so after all proving/verification is finished for caching purposes
  // See: https://github.com/iden3/snarkjs/issues/152
  // @ts-ignore
  await globalThis.curve_bn128.terminate();
  console.timeEnd("Batch Membership Proof Generation");

  return proofs;
};

/**
 * Generate a ZKP for a membership proof
 * @param proofInputs - The inputs to the membership proof circuit
 * @param pathToCircuits - The path to the circuits directory. Only needed for server side proving
 * @returns - The membership ZKP
 */
export const generateMembershipZKP = async (
  proofInputs: MembershipZKPInputs,
  pathToCircuits: string | undefined = undefined
): Promise<ZKP> => {
  if (isNode() && pathToCircuits === undefined) {
    throw new Error(
      "Path to circuits must be provided for server side proving!"
    );
  }

  // For client side proving, we can retrieve circuits from cloud storage
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
