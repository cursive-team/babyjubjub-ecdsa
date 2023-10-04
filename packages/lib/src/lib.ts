const snarkjs = require("snarkjs");
const fs = require("fs");
import { Signature, ZKP, MembershipProofInputs, MerkleProof } from "./types";
import { getPublicInputsFromSignature } from "./witness";
import { publicKeyFromString } from "./sig";
import { generateMerkleProof } from "./merkle";

export const proveMembership = async (
  sig: Signature,
  pubKeys: string[],
  index: number,
  msgHash: bigint
): Promise<ZKP> => {
  const pubKey = publicKeyFromString(pubKeys[index]);

  // Todo: Recover public key from signature, remove index
  const { T, U } = getPublicInputsFromSignature(sig, msgHash, pubKey);

  const merkleProof = await generateMerkleProof(pubKeys, index);

  const proofInputs: MembershipProofInputs = {
    s: sig.s,
    Tx: T.x,
    Ty: T.y,
    Ux: U.x,
    Uy: U.y,
    root: merkleProof.root,
    pathIndices: merkleProof.pathIndices,
    siblings: merkleProof.siblings,
  };

  return await snarkjs.groth16.fullProve(
    proofInputs,
    __dirname + "/circuits/pubkey_membership.wasm",
    __dirname + "/circuits/pubkey_membership.zkey"
  );
};

export const verifyMembership = async (zkProof: ZKP): Promise<boolean> => {
  const { proof, publicSignals } = zkProof;

  const vKey = JSON.parse(
    fs.readFileSync(__dirname + "/circuits/pubkey_membership_vkey.json")
  );

  return await snarkjs.groth16.verify(vKey, publicSignals, proof);
};
