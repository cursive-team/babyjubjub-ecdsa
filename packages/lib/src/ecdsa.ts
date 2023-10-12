const ECSignature = require("elliptic/lib/elliptic/ec/signature");
const BN = require("bn.js");
import { EdwardsPoint, WeierstrassPoint, babyjubjub } from "./babyJubjub";
import { Signature } from "./types";

/**
 * Verifies an ECDSA signature on the baby jubjub curve in Javascript
 * @param sig - The signature to verify
 * @param msgHash - The hash of the message that was signed
 * @param pubKey - The public key of the signer in Short Weierstrass form
 * @returns A boolean indicating whether or not the signature is valid
 */
export const verifyEcdsaSignature = (
  sig: Signature,
  msgHash: bigint,
  pubKey: WeierstrassPoint
): boolean => {
  const ecSignature = new ECSignature({
    r: sig.r.toString(16),
    s: sig.s.toString(16),
  });
  const pubKeyPoint = babyjubjub.ec.curve.point(
    pubKey.x.toString(16),
    pubKey.y.toString(16)
  );
  const ecPubKey = babyjubjub.ec.keyFromPublic(pubKeyPoint);

  return babyjubjub.ec.verify(msgHash, ecSignature, ecPubKey);
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
