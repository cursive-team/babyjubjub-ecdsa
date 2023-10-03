import { WeierstrassPoint } from "./babyJubjub";
import { Signature } from "./types";
import * as hash from "hash.js";

export const derDecode = (encodedSig: string): Signature => {
  const r_length = parseInt(encodedSig.slice(6, 8), 16) * 2; // Multiply by 2 to get length in hex characters
  const s_length =
    parseInt(encodedSig.slice(10 + r_length, 12 + r_length), 16) * 2;

  const r = encodedSig.slice(8, 8 + r_length);
  const s = encodedSig.slice(12 + r_length, 12 + r_length + s_length);

  return { r: hexToBigInt(r), s: hexToBigInt(s) };
};

export const publicKeyFromString = (pubKey: string): WeierstrassPoint => {
  if (pubKey.slice(0, 2) !== "04") {
    throw new Error("Only handle uncompressed public keys for now");
  }

  const pubKeyLength = pubKey.length - 2;
  const x = hexToBigInt(pubKey.slice(2, 2 + pubKeyLength / 2));
  const y = hexToBigInt(pubKey.slice(2 + pubKeyLength / 2));
  return new WeierstrassPoint(x, y);
};

export const hashPublicKey = (pubKey: string): Uint8Array => {
  const pubKeyHash = hash.sha256().update(pubKey).digest("hex");
  return hexToBytes(pubKeyHash);
};

export const hashMessage = (msg: string): bigint => {
  const msgBuffer = Buffer.from(msg);
  return hexToBigInt(msgBuffer.toString("hex"));
};

export const hexToBigInt = (hex: string): bigint => {
  return BigInt(`0x${hex}`);
};

export const bigIntToHex = (bigInt: BigInt): string => {
  return bigInt.toString(16);
};

export const hexToBytes = (hex: string): Uint8Array => {
  return Uint8Array.from(
    hex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
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
