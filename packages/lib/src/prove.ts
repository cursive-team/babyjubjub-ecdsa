const snarkjs = require("snarkjs");
import { v4 as uuidv4 } from "uuid";
import {
  ZKP,
  ZKPInputs,
  MembershipProof,
  ProveArgs,
  BatchProveArgs,
  MerkleProof,
} from "./types";
import { getPublicInputsFromSignature, computeMerkleProof } from "./inputGen";
import { isNode } from "./utils";

/**
 * Generates an ECDSA membership proof for a given signature
 * Proof contains a ZKP as well as information needed for out of circuit verification
 * @param sig - The signature to generate the proof for
 * @param msgHash - The hash of the message that was signed
 * @param publicInputs - Precomputed public inputs in Efficient ECDSA form
 * @param pubKey - The public key used to sign the signature. Only needed if public inputs and merkle proof are not precomputed
 * @param merkleTreeDepth - The depth of the merkle tree used to store public keys
 * @param merkleProof - Precomputed merkle proof
 * @param merkleProofArgs - Arguments to generate the merkle proof. Only needed if merkle proof is not precomputed
 * @param sigNullifierRandomness - Must be random per application. Used to generate unique nullifiers for the signature
 * @param pubKeyNullifierRandomness - Must be random per application. Used to generate unique nullifiers for the public key
 * @param pathToCircuits - The path to the circuits directory. Only needed for server side proving
 * @param enableTiming - Whether or not to log timing information
 * @returns - The membership proof
 */
export const proveMembership = async ({
  sig,
  msgHash,
  publicInputs,
  pubKey,
  merkleTreeDepth,
  merkleProof,
  merkleProofArgs,
  sigNullifierRandomness,
  pubKeyNullifierRandomness,
  pathToCircuits,
  enableTiming,
}: ProveArgs): Promise<MembershipProof> => {
  if (!publicInputs && !merkleProofArgs && !pubKey) {
    throw new Error(
      "Must provide either public inputs, merkle proof args, or public key!"
    );
  }
  if (!merkleTreeDepth) {
    throw new Error("Must provide the merkle tree depth!");
  }
  if (!merkleProof && !merkleProofArgs) {
    throw new Error("Must provide either merkle proof or merkle proof args!");
  }

  const timingUuid = uuidv4();
  enableTiming && console.time(`Membership Proof Generation: ${timingUuid}`);
  enableTiming && console.time(`T and U Generation: ${timingUuid}`);
  let R, T, U;
  if (publicInputs) {
    ({ R, T, U } = publicInputs);
  } else {
    const resolvedPubKey = merkleProofArgs
      ? merkleProofArgs.pubKeys[merkleProofArgs.index]
      : pubKey!;
    ({ R, T, U } = getPublicInputsFromSignature(sig, msgHash, resolvedPubKey));
  }
  enableTiming && console.timeEnd(`T and U Generation: ${timingUuid}`);

  enableTiming && console.time(`Merkle Proof Generation: ${timingUuid}`);
  let resolvedMerkleProof;
  if (merkleProof) {
    resolvedMerkleProof = merkleProof;
  } else {
    const { pubKeys, index, hashFn } = merkleProofArgs!;
    const edwardsPubKeys = await Promise.all(
      pubKeys.map(async (pubKey) => pubKey.toEdwards())
    );
    resolvedMerkleProof = await computeMerkleProof(
      merkleTreeDepth,
      edwardsPubKeys,
      index,
      hashFn
    );
  }
  enableTiming && console.timeEnd(`Merkle Proof Generation: ${timingUuid}`);

  enableTiming && console.time(`ZK Proof Generation: ${timingUuid}`);
  const proofInputs: ZKPInputs = {
    s: sig.s,
    Tx: T.x,
    Ty: T.y,
    Ux: U.x,
    Uy: U.y,
    root: resolvedMerkleProof.root,
    pathIndices: resolvedMerkleProof.pathIndices,
    siblings: resolvedMerkleProof.siblings,
    sigNullifierRandomness: sigNullifierRandomness,
    pubKeyNullifierRandomness: pubKeyNullifierRandomness,
  };
  const zkp = await generateMembershipZKP(proofInputs, pathToCircuits);
  enableTiming && console.timeEnd(`ZK Proof Generation: ${timingUuid}`);
  enableTiming && console.timeEnd(`Membership Proof Generation: ${timingUuid}`);

  return {
    R,
    msgHash,
    zkp,
  };
};

/**
 * Generates ECDSA membership proofs for a list of signatures
 * Can only be used for the same list of public keys and fixed nullifier randomness
 * @param sigs - The signature to generate the proof for
 * @param msgHashes - The hash of the message that was signed
 * @param publicInputs - Precomputed public inputs in Efficient ECDSA form
 * @param pubKeys - The public key used to sign the signature. Only needed if public inputs and merkle proof are not precomputed
 * @param merkleTreeDepth - The depth of the merkle tree used to store public keys
 * @param merkleProofs - Precomputed merkle proof
 * @param merkleProofArgs - Arguments to generate the merkle proof. Only needed if merkle proof is not precomputed
 * @param sigNullifierRandomness - Must be random per application. Used to generate unique nullifiers for the signature
 * @param pubKeyNullifierRandomness - Must be random per application. Used to generate unique nullifiers for the public key
 * @param pathToCircuits - The path to the circuits directory. Only needed for server side proving
 * @param enableTiming - Whether or not to log timing information
 * @returns - The list of membership proofs
 */
export const batchProveMembership = async ({
  sigs,
  msgHashes,
  publicInputs,
  pubKeys,
  merkleTreeDepth,
  merkleProofs,
  merkleProofArgs,
  sigNullifierRandomness,
  pubKeyNullifierRandomness,
  pathToCircuits,
  enableTiming,
}: BatchProveArgs): Promise<MembershipProof[]> => {
  if (!publicInputs && !merkleProofArgs && !pubKeys) {
    throw new Error(
      "Must provide either public inputs, merkle proof args, or public key!"
    );
  }
  if (!merkleTreeDepth) {
    throw new Error("Must provide the merkle tree depth!");
  }
  if (!merkleProofs && !merkleProofArgs) {
    throw new Error("Must provide either merkle proof or merkle proof args!");
  }

  const numProofs = sigs.length;
  if (msgHashes.length !== numProofs) {
    throw new Error(
      "Number of message hashes must match number of signatures!"
    );
  }
  if (publicInputs && publicInputs.length !== numProofs) {
    throw new Error("Number of public inputs must match number of signatures!");
  }
  if (pubKeys && pubKeys.length !== numProofs) {
    throw new Error("Number of public keys must match number of signatures!");
  }
  if (merkleProofs && merkleProofs.length !== numProofs) {
    throw new Error("Number of merkle proofs must match number of signatures!");
  }
  if (merkleProofArgs && merkleProofArgs.indices.length !== numProofs) {
    throw new Error(
      "Number of merkle proof args must match number of signatures!"
    );
  }

  enableTiming && console.time("Batch Membership Proof Generation");
  enableTiming && console.time("Batch Merkle Proof Computation");
  let resolvedMerkleProofs: MerkleProof[];
  let resolvedPubKeys = pubKeys;
  if (merkleProofs) {
    resolvedMerkleProofs = merkleProofs;
  } else {
    const { pubKeys, indices, hashFn } = merkleProofArgs!;
    resolvedPubKeys = indices.map((index) => pubKeys[index]);
    const edwardsPubKeys = await Promise.all(
      pubKeys.map(async (pubKey) => pubKey.toEdwards())
    );
    resolvedMerkleProofs = await Promise.all(
      indices.map(async (index) => {
        return await computeMerkleProof(
          merkleTreeDepth,
          edwardsPubKeys,
          index,
          hashFn
        );
      })
    );
  }
  enableTiming && console.timeEnd("Batch Merkle Proof Computation");

  const proofs = await Promise.all(
    sigs.map(async (sig, i) => {
      return await proveMembership({
        sig,
        msgHash: msgHashes[i],
        publicInputs: publicInputs ? publicInputs[i] : undefined,
        pubKey: resolvedPubKeys ? resolvedPubKeys[i] : undefined,
        merkleTreeDepth,
        merkleProof: resolvedMerkleProofs[i],
        sigNullifierRandomness,
        pubKeyNullifierRandomness,
        pathToCircuits,
        enableTiming,
      });
    })
  );
  enableTiming && console.timeEnd("Batch Membership Proof Generation");

  return proofs;
};

/**
 * Generate a ZKP for a membership proof
 * @param proofInputs - The inputs to the membership proof circuit
 * @param pathToCircuits - The path to the circuits directory. Only required for server side proving
 * @returns - The membership ZKP
 */
export const generateMembershipZKP = async (
  proofInputs: ZKPInputs,
  pathToCircuits?: string
): Promise<ZKP> => {
  if (isNode() && pathToCircuits === undefined) {
    throw new Error(
      "Path to circuits must be provided for server side proving!"
    );
  }

  // For client side proving, we can retrieve circuits from cloud storage
  const wasmPath =
    pathToCircuits !== undefined
      ? pathToCircuits + "pubkey_membership.wasm"
      : "https://storage.googleapis.com/jubmoji-circuits/pubkey_membership.wasm";
  const zkeyPath =
    pathToCircuits !== undefined
      ? pathToCircuits + "pubkey_membership.zkey"
      : "https://storage.googleapis.com/jubmoji-circuits/pubkey_membership.zkey";

  const proof = await snarkjs.groth16.fullProve(
    proofInputs,
    wasmPath,
    zkeyPath
  );

  return proof;
};
