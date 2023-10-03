const ECSignature = require("elliptic/lib/elliptic/ec/signature");
const BN = require("bn.js");
import {
  EdwardsPoint,
  WeierstrassPoint,
  babyjubjub,
  baseField as Fb,
  scalarField as Fs,
  cofactor,
} from "./babyJubjub";
import { Signature } from "./types";
import { hashMessage } from "./sig";

export const privateKeyToPublicKey = (privKey: bigint): WeierstrassPoint => {
  const pubKeyPoint = babyjubjub.g.mul(privKey.toString(16));
  return WeierstrassPoint.fromEllipticPoint(pubKeyPoint);
};

export const verifyEcdsaSignature = (
  sig: Signature,
  message: string,
  pubKey: WeierstrassPoint
): boolean => {
  const msgHash = message;
  const ecSignature = new ECSignature({
    r: sig.r.toString(16),
    s: sig.s.toString(16),
  });
  const pubKeyPoint = babyjubjub.curve.point(
    pubKey.x.toString(16),
    pubKey.y.toString(16)
  );
  const ecPubKey = babyjubjub.keyFromPublic(pubKeyPoint);

  return babyjubjub.verify(msgHash, ecSignature, ecPubKey);
};

export const getPublicInputsFromSignature = (
  sig: Signature,
  msg: string,
  pubKey: WeierstrassPoint
): { T: EdwardsPoint; U: EdwardsPoint } => {
  for (const i of Array(cofactor).keys()) {
    for (const parity of [0, 1]) {
      const r = Fb.add(sig.r, Fb.mul(BigInt(i), Fs.p));
      const rInv = Fs.inv(r);
      let R;
      try {
        R = babyjubjub.curve.pointFromX(new BN(r.toString(16), 16), parity);
      } catch (e) {
        continue;
      }
      const rawT = R.mul(rInv.toString(16));
      const T = WeierstrassPoint.fromEllipticPoint(rawT);
      const m = BigInt(msg);
      const G = babyjubjub.curve.g;
      const rInvm = Fs.neg(Fs.mul(rInv, m));
      const rawU = G.mul(rInvm.toString(16));
      const U = WeierstrassPoint.fromEllipticPoint(rawU);
      const sT = rawT.mul(sig.s.toString(16));
      const rawsTU = sT.add(rawU);
      const sTU = WeierstrassPoint.fromEllipticPoint(rawsTU);

      if (sTU.equals(pubKey)) {
        return { T: T.toEdwards(), U: U.toEdwards() };
      }
    }
  }

  throw new Error("Could not find valid public inputs");
};
