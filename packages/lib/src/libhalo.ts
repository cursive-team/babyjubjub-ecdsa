import { extendHexString } from "./utils";

/**
 * Returns the incrementing nonce string that is actually signed by HaLo chips
 * https://github.com/arx-research/libhalo/blob/master/docs/halo-command-set.md#command-sign_random
 * @param msgNonce incrementing counter
 * @param msgRand rng string added to end
 * @returns hex-encoded string of data to be signed
 */
export const getCounterMessage = (
  msgNonce: number,
  msgRand: string
): string => {
  // Nonce occupies the first 4 bytes of the message
  const nonceString = extendHexString(msgNonce.toString(16), 8);
  // Randomness occupies the next 28 bytes of the message
  const randString = extendHexString(msgRand, 56);
  const msgString = nonceString + randString;
  const counterMessageBuffer = Buffer.concat([
    Buffer.from("\x19Attest counter pk62:\n", "utf8"),
    Buffer.from(msgString, "hex"),
  ]);

  return counterMessageBuffer.toString("hex");
};
