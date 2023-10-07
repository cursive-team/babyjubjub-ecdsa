const snarkjs = require("snarkjs");
const fs = require("fs");
import { EdwardsPoint, WeierstrassPoint, babyjubjub } from "./babyJubjub";
import { computeMerkleRoot } from "./inputGen";
import { EcdsaMembershipProof, ZKP } from "./types";
import { isNode } from "./utils";

export const verifyMembership = async (
  proof: EcdsaMembershipProof,
  pubKeys: WeierstrassPoint[],
  nullifierRandomness: bigint = BigInt(0),
  pathToCircuits: string | undefined = undefined
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
  const computedMerkleRoot = await computeMerkleRoot(edwardsPubKeys);
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

  // @ts-ignore
  await globalThis.curve_bn128.terminate();
  console.timeEnd("Membership Proof Verification");

  return verified;
};

export const batchVerifyMembership = async (
  proofs: EcdsaMembershipProof[],
  pubKeys: WeierstrassPoint[],
  nullifierRandomness: bigint = BigInt(0),
  pathToCircuits: string | undefined = undefined
): Promise<boolean> => {
  if (isNode() && pathToCircuits === undefined) {
    throw new Error(
      "Path to circuits must be provided for server side verification!"
    );
  }

  console.time("Batch Membership Proof Verification");
  console.time("Batch Merkle Root Computation");
  const edwardsPubKeys = pubKeys.map((pubKey) => pubKey.toEdwards());
  const computedMerkleRoot = await computeMerkleRoot(edwardsPubKeys);
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

      return verified;
    })
  );

  // @ts-ignore
  await globalThis.curve_bn128.terminate();
  console.timeEnd("Batch Membership Proof Verification");

  // Could rewrite this to short circuit if any are false verifications,
  // but it might be useful in the future to know which ones failed
  return verified.every((v) => v);
};

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
  const rawU = G.mul(rInvm.toString(16));
  const U = WeierstrassPoint.fromEllipticPoint(rawU);

  return { T: T.toEdwards(), U: U.toEdwards() };
};

export const verifyMembershipZKP = async (
  vKey: any,
  { proof, publicSignals }: ZKP
): Promise<boolean> => {
  return await snarkjs.groth16.verify(vKey, publicSignals, proof);
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
