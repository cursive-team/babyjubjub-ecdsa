// @ts-ignore
import { ZqField } from "ffjavascript";
import { EdwardsPoint } from "./babyJubjub";

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

export type EcdsaMembershipProof = {
  R: EdwardsPoint;
  msgHash: bigint;
  T: EdwardsPoint;
  U: EdwardsPoint;
  zkp: ZKP;
};

export type ZKP = { proof: any; publicSignals: string[] };

export type MembershipZKPInputs = {
  s: bigint;
  root: bigint;
  Tx: bigint;
  Ty: bigint;
  Ux: bigint;
  Uy: bigint;
  pathIndices: number[];
  siblings: bigint[];
  nullifierRandomness: bigint;
};

export interface MerkleProof {
  root: bigint;
  pathIndices: number[];
  siblings: bigint[];
}
