export type Signature = {
  r: BigInt;
  s: BigInt;
};

export type MembershipProofInputs = {
  s: BigInt;
  root: BigInt;
  Tx: BigInt;
  Ty: BigInt;
  Ux: BigInt;
  Uy: BigInt;
  pathIndices: number[];
  siblings: BigInt[];
};

export interface MerkleProof {
  root: BigInt;
  pathIndices: BigInt[];
  siblings: BigInt[];
}

export type ZKP = { proof: string; publicSignals: string };
