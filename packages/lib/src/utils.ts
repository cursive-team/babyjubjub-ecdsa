// @ts-ignore
import { buildPoseidonReference as buildPoseidon } from "circomlibjs";
import { EdwardsPoint, WeierstrassPoint } from "./babyJubjub";
import { MembershipProof, Signature } from "./types";

/**
 * Checks if a string is a hex string
 * @param str - The string to check
 * @returns Whether or not the string is a hex string
 */
export const isHexString = (str: string): boolean => {
  return /^[0-9a-fA-F]+$/.test(str);
};

/**
 * DER decodes a signature
 * @param encodedSig - The encoded signature
 * @returns - The decoded signature
 */
export const derDecodeSignature = (encodedSig: string): Signature => {
  const r_length = parseInt(encodedSig.slice(6, 8), 16) * 2; // Multiply by 2 to get length in hex characters
  const s_length =
    parseInt(encodedSig.slice(10 + r_length, 12 + r_length), 16) * 2;

  const r = encodedSig.slice(8, 8 + r_length);
  const s = encodedSig.slice(12 + r_length, 12 + r_length + s_length);

  return { r: hexToBigInt(r), s: hexToBigInt(s) };
};

/**
 * Converts a public key in hex form to a WeierstrassPoint
 * Reference for key format: https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
 * @param pubKey - The public key in hex form
 * @returns The public key in Weierstrass form
 */
export const publicKeyFromString = (pubKey: string): WeierstrassPoint => {
  if (pubKey.slice(0, 2) !== "04") {
    throw new Error("Only handle uncompressed public keys for now");
  }

  const pubKeyLength = pubKey.length - 2;
  const x = hexToBigInt(pubKey.slice(2, 2 + pubKeyLength / 2));
  const y = hexToBigInt(pubKey.slice(2 + pubKeyLength / 2));

  return new WeierstrassPoint(x, y);
};

/**
 * Hashes an EdwardsPoint to a bigint. Uses the Poseidon hash function
 * @param pubKey - The public key to hash
 * @param hashFn - Optional hash function to use. Defaults to Poseidon
 * @returns The hash of the public key
 */
export const hashEdwardsPublicKey = async (
  pubKey: EdwardsPoint,
  hashFn?: any
): Promise<bigint> => {
  const poseidon = hashFn === undefined ? await buildPoseidon() : hashFn;
  const hash = poseidon([pubKey.x, pubKey.y]);

  return hexToBigInt(poseidon.F.toString(hash, 16));
};

export const serializeMembershipProof = (proof: MembershipProof): string => {
  const R = proof.R.serialize();
  const msgHash = bigIntToHex(proof.msgHash);
  const zkp = proof.zkp;

  return JSON.stringify({ R, msgHash, zkp });
};

export const deserializeMembershipProof = (
  serializedProof: string
): MembershipProof => {
  const proof = JSON.parse(serializedProof);
  const R = EdwardsPoint.deserialize(proof.R);
  const msgHash = hexToBigInt(proof.msgHash);
  const zkp = proof.zkp;

  return { R, msgHash, zkp };
};

export const computeMerkleZeros = async (depth: number): Promise<string[]> => {
  const poseidon = await buildPoseidon();

  let prev = "0";
  const res = [prev];
  for (let i = 0; i < depth; i++) {
    const prevBigInt = BigInt(prev);
    const nextRaw = poseidon([prevBigInt, prevBigInt]);
    const next = hexToBigInt(poseidon.F.toString(nextRaw, 16)).toString();
    res.push(next);
    prev = next;
  }

  return res;
};

export const hexToBigInt = (hex: string): bigint => {
  return BigInt(`0x${hex}`);
};

export const bigIntToHex = (bigInt: BigInt): string => {
  return bigInt.toString(16);
};

export const hexToBytes = (hex: string): Uint8Array => {
  let zeroPaddedHex = hex;
  if (hex.length % 2 !== 0) {
    zeroPaddedHex = "0" + hex;
  }

  return Uint8Array.from(
    zeroPaddedHex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
  );
};

export const bytesToHex = (bytes: Uint8Array): string => {
  return bytes.reduce(
    (str, byte) => str + byte.toString(16).padStart(2, "0"),
    ""
  );
};

export const bytesToBigInt = (bytes: Uint8Array): bigint => {
  return hexToBigInt(bytesToHex(bytes));
};

export const bigIntToBytes = (bigInt: bigint): Uint8Array => {
  return hexToBytes(bigIntToHex(bigInt));
};

export const extendHexString = (hex: string, desiredLength: number): string => {
  const zeros = "0".repeat(desiredLength - hex.length);
  return zeros + hex;
};

export const areAllBigIntsTheSame = (bigInts: bigint[]): boolean => {
  return bigInts.every((bigInt) => bigInt === bigInts[0]);
};

export const areAllBigIntsDifferent = (bigInts: bigint[]): boolean => {
  const bigIntSet = new Set(bigInts);

  return bigIntSet.size === bigInts.length;
};

export const isNode = (): boolean => {
  return typeof window === "undefined";
};
