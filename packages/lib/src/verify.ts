const snarkjs = require("snarkjs");
const fs = require("fs");
import { EdwardsPoint } from "./babyJubjub";
import { computeTUFromR } from "./ecdsa";
import { computeMerkleRoot } from "./inputGen";
import {
  BatchVerifyMembershipArgs,
  MembershipZKPPublicSignals,
  VerifyMembershipArgs,
  ZKP,
} from "./types";
import { isNode } from "./utils";

/**
 * Verifies an ECDSA membership proof
 * Performs in circuit and out of circuit verification
 * Based on the Efficient ECDSA formulation: https://personaelabs.org/posts/efficient-ecdsa-1/
 * Does not check/maintain the list of usedNullifiers, this must be done by the caller
 * @param proof - The membership proof to verify
 * @param pubKeys - The list of public keys comprising the anonymity set for the proof
 * @param sigNullifierRandomness - Optional nullifier randomness used to generate unique nullifiers for signatures
 * @param pathToCircuits - The path to the verification key. Only needed for server side verification
 * @param hashFn - The hash function to use for the merkle tree. Defaults to Poseidon
 * @returns - A boolean indicating whether or not the proof is valid
 */
export const verifyMembership = async ({
  proof,
  pubKeys,
  sigNullifierRandomness,
  pathToCircuits,
  hashFn,
}: VerifyMembershipArgs): Promise<boolean> => {
  if (isNode() && pathToCircuits === undefined) {
    throw new Error(
      "Path to circuits must be provided for server side verification!"
    );
  }

  console.time("Membership Proof Verification");
  const publicSignals = getPublicSignalsFromMembershipZKP(proof.zkp);

  console.time("Merkle Root Verification");
  const edwardsPubKeys = pubKeys.map((pubKey) => pubKey.toEdwards());
  const computedMerkleRoot = await computeMerkleRoot(edwardsPubKeys, hashFn);
  if (computedMerkleRoot !== publicSignals.merkleRoot) {
    return false;
  }
  console.timeEnd("Merkle Root Verification");

  console.time("T and U Verification");
  const { T, U } = publicSignals;
  const { R, msgHash } = proof;
  const { T: computedT, U: computedU } = computeTUFromR(
    R.toWeierstrass(),
    msgHash
  );
  if (!computedT.toEdwards().equals(T) || !computedU.toEdwards().equals(U)) {
    return false;
  }
  console.timeEnd("T and U Verification");

  console.time("Nullifier Verification");
  if (sigNullifierRandomness != publicSignals.sigNullifierRandomness) {
    return false;
  }
  console.timeEnd("Nullifier Verification");

  console.time("Fetching Verification Key");
  const vKey = isNode()
    ? await getVerificationKeyFromFile(pathToCircuits!)
    : await getVerificationKeyFromUrl();
  console.timeEnd("Fetching Verification Key");

  console.time("ZK Proof Verification");
  const verified = await verifyMembershipZKP(vKey, proof.zkp);
  console.timeEnd("ZK Proof Verification");
  console.timeEnd("Membership Proof Verification");

  return verified;
};

/**
 * Verifies a batch of ECDSA membership proofs
 * Must be used with the same list of public keys and nullifier randomness
 * Based on the Efficient ECDSA formulation: https://personaelabs.org/posts/efficient-ecdsa-1/
 * Does not check/maintain the list of usedNullifiers, this must be done by the caller
 * @param proofs - The membership proofs to verify
 * @param pubKeys - The list of public keys comprising the anonymity set for the proof
 * @param sigNullifierRandomness - Optional nullifier randomness used to generate unique nullifiers for signatures
 * @param pathToCircuits - The path to the verification key. Only needed for server side verification
 * @param hashFn - The hash function to use for the merkle tree. Defaults to Poseidon
 * @returns - A boolean indicating whether or not all of the proofs are valid
 */
export const batchVerifyMembership = async ({
  proofs,
  pubKeys,
  sigNullifierRandomness,
  pathToCircuits,
  hashFn,
}: BatchVerifyMembershipArgs): Promise<boolean> => {
  if (isNode() && pathToCircuits === undefined) {
    throw new Error(
      "Path to circuits must be provided for server side verification!"
    );
  }

  console.time("Batch Membership Proof Verification");
  console.time("Batch Merkle Root Computation");
  const edwardsPubKeys = pubKeys.map((pubKey) => pubKey.toEdwards());
  const computedMerkleRoot = await computeMerkleRoot(edwardsPubKeys, hashFn);
  console.timeEnd("Batch Merkle Root Computation");

  console.time("Fetching Verification Key");
  const vKey = isNode()
    ? await getVerificationKeyFromFile(pathToCircuits!)
    : await getVerificationKeyFromUrl();
  console.timeEnd("Fetching Verification Key");

  const verified = await Promise.all(
    proofs.map(async (proof, i) => {
      console.time(`Membership Proof Verification: ${i}`);
      const publicSignals = getPublicSignalsFromMembershipZKP(proof.zkp);

      console.time(`Merkle Root Verification: ${i}`);
      if (computedMerkleRoot !== publicSignals.merkleRoot) {
        return false;
      }
      console.timeEnd(`Merkle Root Verification: ${i}`);

      console.time(`T and U Verification: ${i}`);
      const { T, U } = publicSignals;
      const { R, msgHash } = proof;
      const { T: computedT, U: computedU } = computeTUFromR(
        R.toWeierstrass(),
        msgHash
      );
      if (
        !computedT.toEdwards().equals(T) ||
        !computedU.toEdwards().equals(U)
      ) {
        return false;
      }
      console.timeEnd(`T and U Verification: ${i}`);

      console.time(`Nullifier Verification: ${i}`);
      if (sigNullifierRandomness != publicSignals.sigNullifierRandomness) {
        return false;
      }
      console.timeEnd(`Nullifier Verification: ${i}`);

      console.time(`ZK Proof Verification: ${i}`);
      const verified = await verifyMembershipZKP(vKey, proof.zkp);
      console.timeEnd(`ZK Proof Verification: ${i}`);
      console.timeEnd(`Membership Proof Verification: ${i}`);

      return verified;
    })
  );
  console.timeEnd("Batch Membership Proof Verification");

  return verified.every((v) => v);
};

/**
 * Verifies a zero knowledge proof for a membership proof
 * @param vkey - The verification key for the membership proof
 * @param proof - The zero knowledge proof to verify
 * @param publicInputs - The public inputs to the zero knowledge proof
 * @returns - A boolean indicating whether or not the proof is valid
 */
export const verifyMembershipZKP = async (
  vKey: any,
  { proof, publicSignals }: ZKP
): Promise<boolean> => {
  return await snarkjs.groth16.verify(vKey, publicSignals, proof);
};

/**
 * Gets public signals as typed arguments from a membership zkp
 * @param zkp - The membership zkp
 * @returns - Public signals of the membership zkp
 */
export const getPublicSignalsFromMembershipZKP = (
  zkp: ZKP
): MembershipZKPPublicSignals => {
  const publicSignals = zkp.publicSignals;

  return {
    merkleRoot: BigInt(publicSignals[3]),
    T: new EdwardsPoint(BigInt(publicSignals[4]), BigInt(publicSignals[5])),
    U: new EdwardsPoint(BigInt(publicSignals[6]), BigInt(publicSignals[7])),
    sigNullifier: BigInt(publicSignals[0]),
    sigNullifierRandomness: BigInt(publicSignals[8]),
    pubKeyNullifier: BigInt(publicSignals[1]),
    pubKeyNullifierRandomnessHash: BigInt(publicSignals[2]),
  };
};

const getVerificationKeyFromFile = async (
  pathToCircuits: string
): Promise<any> => {
  const vKey = JSON.parse(
    fs.readFileSync(pathToCircuits + "pubkey_membership_vkey.json")
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
