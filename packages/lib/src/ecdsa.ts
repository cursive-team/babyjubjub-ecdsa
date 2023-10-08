const ECSignature = require("elliptic/lib/elliptic/ec/signature");
const BN = require("bn.js");
import { WeierstrassPoint, babyjubjub } from "./babyJubjub";
import { Signature } from "./types";

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

export const privateKeyToPublicKey = (privKey: bigint): WeierstrassPoint => {
  const pubKeyPoint = babyjubjub.ec.g.mul(privKey.toString(16));

  return WeierstrassPoint.fromEllipticPoint(pubKeyPoint);
};

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

  for (let i = 0; i < babyjubjub.cofactor; i++) {
    for (const parity of [0, 1]) {
      const r = Fb.add(sig.r, Fb.mul(BigInt(i), Fs.p));
      const rInv = Fs.inv(r);
      let R;
      try {
        R = babyjubjub.ec.curve.pointFromX(new BN(r.toString(16), 16), parity);
      } catch (e) {
        continue;
      }
      const u1 = Fs.neg(Fs.mul(msgHash, rInv));
      const u2 = Fs.mul(sig.s, rInv);
      const G = babyjubjub.ec.curve.g;
      const rawPubKey = G.mul(u1.toString(16)).add(R.mul(u2.toString(16)));
      const pubKeyWeierstrass = WeierstrassPoint.fromEllipticPoint(rawPubKey);
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
