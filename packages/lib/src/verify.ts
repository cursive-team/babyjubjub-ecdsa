const snarkjs = require("snarkjs");
const fs = require("fs");
import { v4 as uuidv4 } from "uuid";
import { EdwardsPoint } from "./babyJubjub";
import { computeTUFromR } from "./ecdsa";
import { computeMerkleRoot } from "./inputGen";
import {
  BatchVerifyArgs,
  VerificationResult,
  VerifyArgs,
  ZKP,
  ZKPPublicSignals,
} from "./types";
import { areAllBigIntsDifferent, isNode } from "./utils";

/**
 * Verifies an ECDSA membership proof
 * Performs in circuit and out of circuit verification
 * Based on the Efficient ECDSA formulation: https://personaelabs.org/posts/efficient-ecdsa-1/
 * Does not maintain the list of usedSigNullifiers, this must be done by the caller
 * @param proof - The membership proof to verify
 * @param merkleRoot - Precomputed merkle root for the public key anonymity set
 * @param merkleRootArgs - Arguments to generate the merkle root. Only needed if merkle root is not precomputed
 * @param sigNullifierRandomness - Randomness used to generate signature nullifiers. Must be unique per application
 * @param usedSigNullifiers - The list of used signature nullifiers. Used to prevent double proofs
 * @param pathToCircuits - The path to the verification key. Only needed for server side verification
 * @param enableTiming - Whether or not to log timing information
 * @returns - A boolean indicating whether or not the proof is valid, and a list of newly spent sig nullifiers
 */
export const verifyMembership = async ({
  proof,
  merkleRoot,
  merkleRootArgs,
  sigNullifierRandomness,
  usedSigNullifiers,
  pathToCircuits,
  enableTiming,
}: VerifyArgs): Promise<VerificationResult> => {
  if (isNode() && pathToCircuits === undefined) {
    throw new Error(
      "Path to circuits must be provided for server side verification!"
    );
  }
  if (!merkleRoot && !merkleRootArgs) {
    throw new Error("Must provide either merkle root or merkle root args!");
  }

  const timingUuid = uuidv4();
  enableTiming && console.time(`Membership Proof Verification: ${timingUuid}`);
  const publicSignals = getPublicSignalsFromMembershipZKP(proof.zkp);

  enableTiming && console.time(`Merkle Root Verification: ${timingUuid}`);
  let resolvedMerkleRoot;
  if (merkleRoot) {
    resolvedMerkleRoot = merkleRoot;
  } else {
    const { pubKeys, hashFn } = merkleRootArgs!;
    const edwardsPubKeys = pubKeys.map((pubKey) => pubKey.toEdwards());
    resolvedMerkleRoot = await computeMerkleRoot(edwardsPubKeys, hashFn);
  }
  if (resolvedMerkleRoot !== publicSignals.merkleRoot) {
    return { verified: false };
  }
  enableTiming && console.timeEnd(`Merkle Root Verification: ${timingUuid}`);

  enableTiming && console.time(`T and U Verification: ${timingUuid}`);
  const { T, U } = computeTUFromR(proof.R, proof.msgHash);
  if (!T.equals(publicSignals.T) || !U.equals(publicSignals.U)) {
    return { verified: false };
  }
  enableTiming && console.timeEnd(`T and U Verification: ${timingUuid}`);

  enableTiming && console.time(`Nullifier Verification: ${timingUuid}`);
  if (sigNullifierRandomness !== publicSignals.sigNullifierRandomness) {
    return { verified: false };
  }
  if (
    usedSigNullifiers &&
    usedSigNullifiers.includes(publicSignals.sigNullifier)
  ) {
    return { verified: false };
  }
  enableTiming && console.timeEnd(`Nullifier Verification: ${timingUuid}`);

  enableTiming && console.time(`Fetching Verification Key: ${timingUuid}`);
  const vKey = isNode()
    ? await getVerificationKeyFromFile(pathToCircuits!)
    : await getVerificationKeyFromUrl();
  enableTiming && console.timeEnd(`Fetching Verification Key: ${timingUuid}`);

  enableTiming && console.time(`ZK Proof Verification: ${timingUuid}`);
  const verified = await verifyMembershipZKP(vKey, proof.zkp);
  if (!verified) {
    return { verified: false };
  }
  enableTiming && console.timeEnd(`ZK Proof Verification: ${timingUuid}`);
  enableTiming &&
    console.timeEnd(`Membership Proof Verification: ${timingUuid}`);

  return {
    verified: true,
    consumedSigNullifiers: [publicSignals.sigNullifier],
  };
};

/**
 * Verifies a batch of ECDSA membership proofs
 * Must be used with the same list of public keys and nullifier randomness
 * Based on the Efficient ECDSA formulation: https://personaelabs.org/posts/efficient-ecdsa-1/
 * Does not maintain the list of usedSigNullifiers, this must be done by the caller
 * @param proofs - The membership proofs to verify
 * @param merkleRoot - Precomputed merkle root for the public key anonymity set
 * @param merkleRootArgs - Arguments to generate the merkle root. Only needed if merkle root is not precomputed
 * @param sigNullifierRandomness - Randomness used to generate signature nullifiers. Must be unique per application
 * @param usedSigNullifiers - The list of used signature nullifiers. Used to prevent double proofs
 * @param pathToCircuits - The path to the verification key. Only needed for server side verification
 * @param enableTiming - Whether or not to log timing information
 * @returns - A boolean indicating whether or not the proof is valid, and a list of newly spent sig nullifiers
 */
export const batchVerifyMembership = async ({
  proofs,
  merkleRoot,
  merkleRootArgs,
  sigNullifierRandomness,
  usedSigNullifiers,
  pathToCircuits,
  enableTiming,
}: BatchVerifyArgs): Promise<VerificationResult> => {
  if (isNode() && pathToCircuits === undefined) {
    throw new Error(
      "Path to circuits must be provided for server side verification!"
    );
  }
  if (!merkleRoot && !merkleRootArgs) {
    throw new Error("Must provide either merkle root or merkle root args!");
  }

  enableTiming && console.time("Batch Membership Proof Verification");
  enableTiming && console.time("Batch Merkle Root Computation");
  let resolvedMerkleRoot: bigint;
  if (merkleRoot) {
    resolvedMerkleRoot = merkleRoot;
  } else {
    const { pubKeys, hashFn } = merkleRootArgs!;
    const edwardsPubKeys = pubKeys.map((pubKey) => pubKey.toEdwards());
    resolvedMerkleRoot = await computeMerkleRoot(edwardsPubKeys, hashFn);
  }
  enableTiming && console.timeEnd("Batch Merkle Root Computation");

  const verificationResults = await Promise.all(
    proofs.map(async (proof) => {
      return await verifyMembership({
        proof,
        merkleRoot: resolvedMerkleRoot,
        sigNullifierRandomness,
        usedSigNullifiers,
        pathToCircuits,
        enableTiming,
      });
    })
  );
  if (!verificationResults.every((r) => r.verified)) {
    return { verified: false };
  }

  const allConsumedSigNullifiers: bigint[] = verificationResults.flatMap(
    (result) => result.consumedSigNullifiers || []
  );
  if (!areAllBigIntsDifferent(allConsumedSigNullifiers)) {
    return { verified: false };
  }
  enableTiming && console.timeEnd("Batch Membership Proof Verification");

  return {
    verified: true,
    consumedSigNullifiers: allConsumedSigNullifiers,
  };
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
): ZKPPublicSignals => {
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
