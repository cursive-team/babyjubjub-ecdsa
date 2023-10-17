const elliptic = require("elliptic");
// @ts-ignore
import { ZqField } from "ffjavascript";
import * as hash from "hash.js";
import { BabyJubJub } from "./types";
import { bigIntToHex, hexToBigInt } from "./utils";

// Define short Weierstrass parameters
const curveOptions = {
  p: "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
  prime: null,
  a: "10216f7ba065e00de81ac1e7808072c9b8114d6d7de87adb16a0a72f1a91f6a0",
  b: "23d885f647fed5743cad3d1ee4aba9c043b4ac0fc2766658a410efdeb21f706e",
  g: [
    "1fde0a3cac7cb46b36c79f4c0a7a732e38c2c7ee9ac41f44392a07b748a0869f",
    "203a710160811d5c07ebaeb8fe1d9ce201c66b970d66f18d0d2b264c195309aa",
  ],
  gRed: false,
  n: "60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1",
  type: "short",
};

// Initialize Babyjubjub curve using short Weierstrass parameters
const ShortWeierstrassCurve = elliptic.curve.short;
const curve = new ShortWeierstrassCurve(curveOptions);
const ec = new elliptic.ec({
  curve: { curve, g: curve.g, n: curve.n, hash: hash.sha256 },
});
const baseField = new ZqField(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);
const scalarField = new ZqField(
  "2736030358979909402780800718157159386076813972158567259200215660948447373041"
);
const cofactor = 8;
const scalarFieldBitLength = 251;

export const babyjubjub: BabyJubJub = {
  ec,
  Fb: baseField,
  Fs: scalarField,
  cofactor,
  scalarFieldBitLength,
};

export interface CurvePoint {
  x: bigint;
  y: bigint;

  equals(other: CurvePoint): boolean;

  isInfinity(): boolean;

  toString(): string;
}

export class WeierstrassPoint implements CurvePoint {
  public x: bigint;
  public y: bigint;

  constructor(x: bigint, y: bigint) {
    this.x = x;
    this.y = y;
  }

  equals(other: CurvePoint): boolean {
    return (
      this.x.toString() === other.x.toString() &&
      this.y.toString() === other.y.toString()
    );
  }

  static infinity(): WeierstrassPoint {
    return new WeierstrassPoint(BigInt(0), BigInt(0));
  }

  isInfinity(): boolean {
    return this.x === BigInt(0) && this.y === BigInt(0);
  }

  // Converts from an elliptic.js curve point to a WeierstrassPoint
  static fromEllipticPoint(point: any): WeierstrassPoint {
    if (point.isInfinity()) {
      return this.infinity();
    }

    return new WeierstrassPoint(
      BigInt(point.getX().toString(10)),
      BigInt(point.getY().toString(10))
    );
  }

  // Based on conversion formulae: https://www-fourier.univ-grenoble-alpes.fr/mphell/doc-v5/conversion_weierstrass_edwards.html
  toEdwards(): EdwardsPoint {
    if (this.isInfinity()) {
      return EdwardsPoint.infinity();
    }

    const Fb = baseField;
    const malpha = Fb.div(BigInt(168698), BigInt(3));
    const mx = BigInt(Fb.sub(BigInt(this.x.toString()), malpha));
    const my = BigInt(this.y);

    const ex = Fb.div(mx, my);
    const ey = Fb.div(Fb.sub(mx, BigInt(1)), Fb.add(mx, BigInt(1)));
    return new EdwardsPoint(ex, ey);
  }

  toString(): string {
    return `Weierstrass: (${this.x.toString()}, ${this.y.toString()})`;
  }

  serialize(): string {
    return JSON.stringify({
      x: bigIntToHex(this.x),
      y: bigIntToHex(this.y),
    });
  }

  static deserialize(serialized: string): WeierstrassPoint {
    const { x, y } = JSON.parse(serialized);
    return new WeierstrassPoint(hexToBigInt(x), hexToBigInt(y));
  }
}

export class EdwardsPoint implements CurvePoint {
  public x: bigint;
  public y: bigint;

  constructor(x: bigint, y: bigint) {
    this.x = x;
    this.y = y;
  }

  equals(other: CurvePoint): boolean {
    return (
      this.x.toString() === other.x.toString() &&
      this.y.toString() === other.y.toString()
    );
  }

  static infinity(): EdwardsPoint {
    return new EdwardsPoint(BigInt(0), BigInt(1));
  }

  isInfinity(): boolean {
    return this.x === BigInt(0) && this.y === BigInt(1);
  }

  // Based on conversion formulae: https://www-fourier.univ-grenoble-alpes.fr/mphell/doc-v5/conversion_weierstrass_edwards.html
  toWeierstrass(): WeierstrassPoint {
    if (this.isInfinity()) {
      return WeierstrassPoint.infinity();
    }

    const Fb = baseField;
    const mA = BigInt(168698);
    const mB = BigInt(1);
    const mx = Fb.div(Fb.add(BigInt(1), this.y), Fb.sub(BigInt(1), this.y));
    const my = Fb.div(
      Fb.add(BigInt(1), this.y),
      Fb.mul(Fb.sub(BigInt(1), this.y), this.x)
    );

    const sx = Fb.div(Fb.add(mx, Fb.div(mA, BigInt(3))), mB);
    const sy = Fb.div(my, mB);

    return new WeierstrassPoint(sx, sy);
  }

  toString(): string {
    return `Edwards: (${this.x.toString()}, ${this.y.toString()})`;
  }

  serialize(): string {
    return JSON.stringify({
      x: bigIntToHex(this.x),
      y: bigIntToHex(this.y),
    });
  }

  static deserialize(serialized: string): EdwardsPoint {
    const { x, y } = JSON.parse(serialized);
    return new EdwardsPoint(hexToBigInt(x), hexToBigInt(y));
  }
}
