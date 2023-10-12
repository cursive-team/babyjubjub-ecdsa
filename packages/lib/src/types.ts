// @ts-ignore
import { ZqField } from "ffjavascript";
import { EdwardsPoint, WeierstrassPoint } from "./babyJubjub";

export type BabyJubJub = {
  ec: any;
  Fb: ZqField;
  Fs: ZqField;
  cofactor: number;
};

export type Signature = {
  r: bigint;
  s: bigint;
};

// Contents of a proof for demonstrating a valid BabyJubjub ECDSA
// signature without revealing the signature's s value
// Based on the Efficient ECDSA formulation: https://personaelabs.org/posts/efficient-ecdsa-1/
export interface MembershipProof {
  R: EdwardsPoint;
  msgHash: bigint;
  zkp: ZKP;
}

export interface PublicInputs {
  R: EdwardsPoint;
  T: EdwardsPoint;
  U: EdwardsPoint;
}

// Arguments needed to compute a merkle proof
export interface MerkleProofArgs {
  pubKeys: WeierstrassPoint[];
  index: number;
  hashFn?: any;
}

// Arguments needed to batch compute merkle proofs
export interface BatchMerkleProofArgs {
  pubKeys: WeierstrassPoint[];
  indices: number[];
  hashFn?: any;
}

// Arguments needed to compute a merkle root
export interface MerkleRootArgs {
  pubKeys: WeierstrassPoint[];
  hashFn?: any;
}

// Arguments needed to generate a membership proof
export interface ProveArgs {
  sig: Signature;
  msgHash: bigint;
  publicInputs?: PublicInputs;
  pubKey?: WeierstrassPoint;
  merkleProof?: MerkleProof;
  merkleProofArgs?: MerkleProofArgs;
  sigNullifierRandomness: bigint;
  pubKeyNullifierRandomness: bigint;
  pathToCircuits?: string;
  enableTiming?: boolean;
}

// Arguments needed to batch generate membership proofs
export interface BatchProveArgs {
  sigs: Signature[];
  msgHashes: bigint[];
  publicInputs?: PublicInputs[];
  pubKeys?: WeierstrassPoint[];
  merkleProofs?: MerkleProof[];
  merkleProofArgs?: BatchMerkleProofArgs;
  sigNullifierRandomness: bigint;
  pubKeyNullifierRandomness: bigint;
  pathToCircuits?: string;
  enableTiming?: boolean;
}

// Arguments needed to verify a membership proof
export interface VerifyArgs {
  proof: MembershipProof;
  merkleRoot?: bigint;
  merkleRootArgs?: MerkleRootArgs;
  sigNullifierRandomness: bigint;
  usedSigNullifiers?: bigint[];
  pathToCircuits?: string;
  enableTiming?: boolean;
}

// Arguments needed to batch verify membership proofs
export interface BatchVerifyArgs {
  proofs: MembershipProof[];
  merkleRoot?: bigint;
  merkleRootArgs?: MerkleRootArgs;
  sigNullifierRandomness: bigint;
  usedSigNullifiers?: bigint[];
  pathToCircuits?: string;
  enableTiming?: boolean;
}

export type VerificationResult = {
  verified: boolean;
  consumedSigNullifiers?: bigint[];
};

// Zero knowledge proof generated by snarkjs
export type ZKP = { proof: any; publicSignals: string[] };

// Inputs to the membership proof circuit
// Similar to inputs for Spartan-ecdsa membership circuit:
// https://github.com/personaelabs/spartan-ecdsa/blob/main/packages/circuits/eff_ecdsa_membership/pubkey_membership.circom
// Includes nullifierRandomness for generating unique nullifiers
export type ZKPInputs = {
  s: bigint;
  root: bigint;
  Tx: bigint;
  Ty: bigint;
  Ux: bigint;
  Uy: bigint;
  pathIndices: number[];
  siblings: bigint[];
  sigNullifierRandomness: bigint;
  pubKeyNullifierRandomness: bigint;
};

// Typed public signals for the membership proof circuit
export type ZKPPublicSignals = {
  merkleRoot: bigint;
  T: EdwardsPoint;
  U: EdwardsPoint;
  sigNullifier: bigint;
  sigNullifierRandomness: bigint;
  pubKeyNullifier: bigint;
  pubKeyNullifierRandomnessHash: bigint;
};

export interface MerkleProof {
  root: bigint;
  pathIndices: number[];
  siblings: bigint[];
}
