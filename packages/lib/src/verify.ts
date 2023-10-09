const snarkjs = require("snarkjs");
const fs = require("fs");
import { EdwardsPoint, WeierstrassPoint, babyjubjub } from "./babyJubjub";
import { computeMerkleRoot } from "./inputGen";
import { EcdsaMembershipProof, ZKP } from "./types";
import { isNode } from "./utils";

/**
 * Verifies an ECDSA membership proof
 * Performs in circuit and out of circuit verification
 * Based on the Efficient ECDSA formulation: https://personaelabs.org/posts/efficient-ecdsa-1/
 * Does not check/maintain the list of usedNullifiers, this must be done by the caller
 * @param proof - The membership proof to verify
 * @param pubKeys - The list of public keys comprising the anonymity set for the proof
 * @param nullifierRandomness - Optional nullifier randomness used to generate unique nullifiers
 * @param pathToCircuits - The path to the verification key. Only needed for server side verification
 * @param hashFn - The hash function to use for the merkle tree. Defaults to Poseidon
 * @returns - A boolean indicating whether or not the proof is valid
 */
export const verifyMembership = async (
  proof: EcdsaMembershipProof,
  pubKeys: WeierstrassPoint[],
  nullifierRandomness: bigint = BigInt(0),
  pathToCircuits: string | undefined = undefined,
  hashFn: any = undefined
): Promise<boolean> => {
  if (isNode() && pathToCircuits === undefined) {
    throw new Error(
      "Path to circuits must be provided for server side verification!"
    );
  }

  console.time("Membership Proof Verification");
  console.time("Merkle Root Verification");
  const publicSignals = proof.zkp.publicSignals;
  const merkleRoot = BigInt(publicSignals[1]);
  const edwardsPubKeys = pubKeys.map((pubKey) => pubKey.toEdwards());
  const computedMerkleRoot = await computeMerkleRoot(edwardsPubKeys, hashFn);
  if (computedMerkleRoot !== merkleRoot) {
    return false;
  }
  console.timeEnd("Merkle Root Verification");

  console.time("T and U Verification");
  const [Tx, Ty, Ux, Uy] = publicSignals.slice(2, 6).map(BigInt);
  const T = new EdwardsPoint(Tx, Ty);
  const U = new EdwardsPoint(Ux, Uy);
  const { R, msgHash } = proof;
  const { T: computedT, U: computedU } = await recoverTUFromProof(R, msgHash);
  if (!computedT.equals(T) || !computedU.equals(U)) {
    return false;
  }
  console.timeEnd("T and U Verification");

  console.time("Nullifier Verification");
  const proofNullifierRandomness = BigInt(publicSignals[6]);
  if (proofNullifierRandomness !== nullifierRandomness) {
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

  // snarkjs will not terminate this object automatically
  // We should do so after all proving/verification is finished for caching purposes
  // See: https://github.com/iden3/snarkjs/issues/152
  // @ts-ignore
  await globalThis.curve_bn128.terminate();
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
 * @param nullifierRandomness - Optional nullifier randomness used to generate unique nullifiers
 * @param pathToCircuits - The path to the verification key. Only needed for server side verification
 * @param hashFn - The hash function to use for the merkle tree. Defaults to Poseidon
 * @returns - A boolean indicating whether or not all of the proofs are valid
 */
export const batchVerifyMembership = async (
  proofs: EcdsaMembershipProof[],
  pubKeys: WeierstrassPoint[],
  nullifierRandomness: bigint = BigInt(0),
  pathToCircuits: string | undefined = undefined,
  hashFn: any = undefined
): Promise<boolean> => {
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
      console.time(`Merkle Root Verification: ${i}`);
      const publicSignals = proof.zkp.publicSignals;
      const merkleRoot = BigInt(publicSignals[1]);
      if (computedMerkleRoot !== merkleRoot) {
        return false;
      }
      console.timeEnd(`Merkle Root Verification: ${i}`);

      console.time(`T and U Verification: ${i}`);
      const [Tx, Ty, Ux, Uy] = publicSignals.slice(2, 6).map(BigInt);
      const T = new EdwardsPoint(Tx, Ty);
      const U = new EdwardsPoint(Ux, Uy);
      const { R, msgHash } = proof;
      const { T: computedT, U: computedU } = await recoverTUFromProof(
        R,
        msgHash
      );
      if (!computedT.equals(T) || !computedU.equals(U)) {
        return false;
      }
      console.timeEnd(`T and U Verification: ${i}`);

      console.time(`Nullifier Verification: ${i}`);
      const proofNullifierRandomness = BigInt(publicSignals[6]);
      if (proofNullifierRandomness !== nullifierRandomness) {
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

  // snarkjs will not terminate this object automatically
  // We should do so after all proving/verification is finished for caching purposes
  // See: https://github.com/iden3/snarkjs/issues/152
  // @ts-ignore
  await globalThis.curve_bn128.terminate();
  console.timeEnd("Batch Membership Proof Verification");

  // Could rewrite this to short circuit if any are false verifications,
  // but it might be useful in the future to know which ones failed
  return verified.every((v) => v);
};

/**
 * Recovers public parameters T, U of the membership proof based on the provided R value
 * This ensures that T, U were generated appropriately
 * See: https://hackmd.io/HQZxucnhSGKT_VfNwB6wOw?view
 * @param R - The R value of the membership proof
 * @param msgHash - The hash of the message signed by the signature
 * @returns - The public parameters T, U
 */
export const recoverTUFromProof = async (
  R: EdwardsPoint,
  msgHash: bigint
): Promise<{ T: EdwardsPoint; U: EdwardsPoint }> => {
  const Fs = babyjubjub.Fs;

  const shortR = R.toWeierstrass();
  const r = shortR.x % Fs.p;
  const rInv = Fs.inv(r);
  const ecR = babyjubjub.ec.curve.point(
    shortR.x.toString(16),
    shortR.y.toString(16)
  );
  const ecT = ecR.mul(rInv.toString(16));
  const T = WeierstrassPoint.fromEllipticPoint(ecT);
  const G = babyjubjub.ec.curve.g;
  const rInvm = Fs.neg(Fs.mul(rInv, msgHash));
  const ecU = G.mul(rInvm.toString(16));
  const U = WeierstrassPoint.fromEllipticPoint(ecU);

  return { T: T.toEdwards(), U: U.toEdwards() };
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
 * Gets the nullifier from an ECDSA membership proof
 * Extracts the nullifier from the membership proof's zero knowledge proof's public inputs
 * Should be used to enforce that nullifiers are unique
 * @param proof - The membership proof to get the nullifier from
 * @returns - The nullifier as a bigint
 */
export const getNullifierFromMembershipProof = (
  proof: EcdsaMembershipProof
): bigint => {
  const publicSignals = proof.zkp.publicSignals;

  return BigInt(publicSignals[0]);
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
