import { EdwardsPoint, WeierstrassPoint } from "./babyJubjub";
import { Signature } from "./types";
import { buildPoseidon } from "circomlibjs";

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

export const hashPublicKey = async (pubKey: string): Promise<Uint8Array> => {
  const pubKeyPoint = publicKeyFromString(pubKey);
  const poseidon = await buildPoseidon();
  const hash = poseidon([
    bigIntToBytes(pubKeyPoint.x),
    bigIntToBytes(pubKeyPoint.y),
  ]);

  return hexToBytes(poseidon.F.toString(hash, 16));
};

export const hashEdwardsPublicKey = async (
  pubKey: EdwardsPoint
): Promise<bigint> => {
  const poseidon = await buildPoseidon();
  const hash = poseidon([pubKey.x, pubKey.y]);
  return hexToBigInt(poseidon.F.toString(hash, 16));
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
  let zeroPaddedHex = hex;
  if (hex.length % 2 !== 0) {
    zeroPaddedHex = "0" + hex;
  }

  return Uint8Array.from(
    zeroPaddedHex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
  );
};

export const hexToBytesLE = (hex: string): Uint8Array => {
  let zeroPaddedHex = hex;
  if (hex.length % 2 !== 0) {
    zeroPaddedHex = "0" + hex;
  }

  return Uint8Array.from(
    zeroPaddedHex
      .match(/.{1,2}/g)!
      .map((byte) => parseInt(byte, 16))
      .reverse()
  );
};

export const bytesToHex = (bytes: Uint8Array): string => {
  return bytes.reduce(
    (str, byte) => str + byte.toString(16).padStart(2, "0"),
    ""
  );
};

export const bytesToHexLE = (bytes: Uint8Array): string => {
  return bytes.reduce(
    (str, byte) => byte.toString(16).padStart(2, "0") + str,
    ""
  );
};

export const bytesToBigInt = (bytes: Uint8Array): bigint => {
  return hexToBigInt(bytesToHex(bytes));
};

export const bytesToBigIntLE = (bytes: Uint8Array): bigint => {
  return hexToBigInt(bytesToHexLE(bytes));
};

export const bigIntToBytes = (bigInt: bigint): Uint8Array => {
  return hexToBytes(bigIntToHex(bigInt));
};

export const bigIntToBytesLE = (bigInt: bigint): Uint8Array => {
  return hexToBytesLE(bigIntToHex(bigInt));
};
