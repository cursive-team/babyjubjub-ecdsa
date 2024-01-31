const BN = require("bn.js");
const ECSignature = require("elliptic/lib/elliptic/ec/signature");

import { EdwardsPoint, WeierstrassPoint, babyjubjub } from "./babyJubjub";
import { Signature } from "./types";
import { hexToBigInt, bigIntToHex, derDecodeSignature } from "./utils";
import { sha256 } from "js-sha256";

/**
 * Compute the hash of a message using the ECDSA algorithm
 * @param msg
 * @returns hash as a hex string
 */
const getECDSAMessageHash = (msg: string | Buffer): string => {
  let msgBuffer;
  if (typeof msg === "string") {
    msgBuffer = Buffer.from(msg, "utf-8");
  } else {
    msgBuffer = msg;
  }
  const hasher = sha256.create();
  const hash = hasher.update(msgBuffer).hex();

  // As part of the ECDSA algorithm, we truncate the hash to its left n bits,
  // where n is the bit length of the order of the curve.
  // Truncation includes any leading zeros, so we first pad the hash to the full digest length
  const HASH_DIGEST_LENGTH = 256;
  const hashBits = hexToBigInt(hash)
    .toString(2)
    .padStart(HASH_DIGEST_LENGTH, "0");
  const truncatedBits = hashBits.slice(0, babyjubjub.scalarFieldBitLength);
  const msgHash = BigInt("0b" + truncatedBits);

  // This addresses a quirk of the ellptic.js library where
  // the message hash is truncated oddly. For some reason, the
  // truncation is based on the byte length of the message hash * 8
  // rather than the bit length, which means the truncation is
  // incorrect when we have a message hash that is not a multiple
  // of 8 bits. This addresses that issue by padding the message
  // with some zeros which will be truncated by the library.
  // https://github.com/indutny/elliptic/blob/43ac7f230069bd1575e1e4a58394a512303ba803/lib/elliptic/ec/index.js#L82
  let msgHashPadded = msgHash;
  const msgHashBN = new BN(bigIntToHex(msgHash), 16);
  const delta = msgHashBN.byteLength() * 8 - babyjubjub.ec.n.bitLength();

  // Given that we expect the message hash to be truncated to at most 251 bits,
  // the following condition is only true if delta is equal to 5
  if (delta > 0) {
    msgHashPadded = BigInt("0b" + msgHash.toString(2) + "0".repeat(delta));
  }

  return bigIntToHex(msgHashPadded);
};

/**
 * Generates a new key pair for the baby jubjub curve
 * @returns verifyingKey, signingKey (pubKey and privKey)
 */
export const generateSignatureKeyPair = (): {
  signingKey: string;
  verifyingKey: string;
} => {
  const keyPair = babyjubjub.ec.genKeyPair();

  const pubKey = keyPair.getPublic();
  const privKey = keyPair.getPrivate();

  return {
    verifyingKey: pubKey.encode("hex"),
    signingKey: privKey.toString("hex"),
  };
};

/**
 * Signs a message using the baby jubjub curve
 * @param signingKey - The private key, hex encoded
 * @param data - The message to sign
 * @returns The signature in DER format, hex encoded
 */
export const sign = (signingKey: string, data: string | Buffer): string => {
  const key = babyjubjub.ec.keyFromPrivate(signingKey, "hex");
  const msgHash = getECDSAMessageHash(data);
  const signature = key.sign(msgHash, "hex", {
    canonical: true,
  });
  const signatureDER = signature.toDER();
  return Buffer.from(signatureDER).toString("hex");
};

/**
 * Verifies an ECDSA signature on the baby jubjub curve
 * @param verifyingKey - The public key of the signer, hex encoded
 * @param data - The message that was signed
 * @param signature - The signature in DER format, hex encoded
 * @returns boolean indicating whether or not the signature is valid
 */
export const verify = (
  verifyingKey: string,
  data: string | Buffer,
  signature: string
): boolean => {
  const key = babyjubjub.ec.keyFromPublic(verifyingKey, "hex");
  const msgHash = getECDSAMessageHash(data);
  const sig = derDecodeSignature(signature);
  return babyjubjub.ec.verify(
    msgHash,
    new ECSignature({
      r: sig.r.toString(16),
      s: sig.s.toString(16),
    }),
    key
  );
};

/**
 * Converts a private key to a public key on the baby jubjub curve
 * @param privKey - The private key to convert
 * @returns The public key in Short Weierstrass form
 */
export const privateKeyToPublicKey = (privKey: bigint): WeierstrassPoint => {
  const pubKeyPoint = babyjubjub.ec.g.mul(privKey.toString(16));

  return WeierstrassPoint.fromEllipticPoint(pubKeyPoint);
};

/**
 * Recovers the public key index from a signature
 * @param sig - The signature to recover the public key from
 * @param msgHash - The hash of the message that was signed
 * @param pubKeys - The list of public keys to check
 * @throws If a public key cannot be recovered from the signature
 * @throws If the public key cannot be found in the list of public keys
 * @returns The index of the recovered public key
 */
export const recoverPubKeyIndexFromSignature = (
  sig: Signature,
  msgHash: bigint,
  pubKeys: WeierstrassPoint[]
): number => {
  const Fb = babyjubjub.Fb;
  const Fs = babyjubjub.Fs;

  const pubKeyEdwardsList = pubKeys.map((pubKey) => {
    return pubKey.toEdwards();
  });

  // Because the cofactor is > 1, we must check multiple points
  // See public key recovery algorithm: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
  for (let i = 0; i < babyjubjub.cofactor; i++) {
    for (const parity of [0, 1]) {
      const r = Fb.add(sig.r, Fb.mul(BigInt(i), Fs.p));
      const rInv = Fs.inv(r);
      let R;
      try {
        // The following will throw an error if the point is not on the curve
        R = babyjubjub.ec.curve.pointFromX(new BN(r.toString(16), 16), parity);
      } catch (e) {
        continue;
      }
      const u1 = Fs.neg(Fs.mul(msgHash, rInv));
      const u2 = Fs.mul(sig.s, rInv);
      const G = babyjubjub.ec.curve.g;
      const ecPubKey = G.mul(u1.toString(16)).add(R.mul(u2.toString(16)));
      const pubKeyWeierstrass = WeierstrassPoint.fromEllipticPoint(ecPubKey);
      const pubKeyEdwards = pubKeyWeierstrass.toEdwards();
      const index = pubKeyEdwardsList.findIndex((pubKey) =>
        pubKey.equals(pubKeyEdwards)
      );

      if (index !== -1) {
        return index;
      }
    }
  }

  throw new Error("Could not recover public key from signature");
};

/**
 * Computes public parameters T, U of the membership proof based on the provided R value
 * This ensures that T, U were generated appropriately
 * See: https://hackmd.io/HQZxucnhSGKT_VfNwB6wOw?view
 * @param R - The R value of the membership proof
 * @param msgHash - The hash of the message signed by the signature
 * @returns - The public parameters T, U
 */
export const computeTUFromR = (
  R: EdwardsPoint,
  msgHash: bigint
): { T: EdwardsPoint; U: EdwardsPoint } => {
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
  const ecU = G.mul(rInvm.toString(16));
  const U = WeierstrassPoint.fromEllipticPoint(ecU);

  return { T: T.toEdwards(), U: U.toEdwards() };
};
