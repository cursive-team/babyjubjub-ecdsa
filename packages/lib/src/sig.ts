import { Signature } from "./types";

export const derDecode = (encodedSig: string): Signature => {
  const r_length = parseInt(encodedSig.slice(6, 8), 16) * 2; // Multiply by 2 to get length in hex characters
  const s_length =
    parseInt(encodedSig.slice(10 + r_length, 12 + r_length), 16) * 2;

  const r = encodedSig.slice(8, 8 + r_length);
  const s = encodedSig.slice(12 + r_length, 12 + r_length + s_length);

  return { r: hexToBigInt(r), s: hexToBigInt(s) };
};

export const hashMessage = (msg: string): BigInt => {
  const msgBuffer = Buffer.from(msg);
  return hexToBigInt(msgBuffer.toString("hex"));
};

export const hexToBigInt = (hex: string): BigInt => {
  return BigInt(`0x${hex}`);
};
