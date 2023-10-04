import { hashEdwardsPublicKey, publicKeyFromString } from "../src/utils";
import { EdwardsPoint, WeierstrassPoint } from "../src/babyJubjub";
import { buildPoseidon } from "circomlibjs";

describe("signature and key parsing utilities", () => {
  test("should parse an encoded public key", () => {
    const encodedPubKey =
      "041052d6da0c3d7248e39e08912e2daa53c4e54cd9f2d96e3702fa15e77b199a501cd835bbddcc77134dc59dbbde2aa702183a68c90877906a31536eef972fac36";

    const parsedPubKey = publicKeyFromString(encodedPubKey);

    const expectedPubKey = new WeierstrassPoint(
      BigInt(
        "7383369888919701441480368741745717804236448589785295824485316386504973064784"
      ),
      BigInt(
        "13046769583748125084667126323794391074141340611556711664428099286902963678262"
      )
    );

    expect(parsedPubKey).toEqual(expectedPubKey);
  });

  test("should hash an Edwards public key correctly", async () => {
    const pubKey = new EdwardsPoint(
      BigInt(
        "11513997017404587999039986937421722453331811838930011493225155799998969860257"
      ),
      BigInt(
        "15702184800053625297652133943476286357553803483146409610785811576616213183541"
      )
    );

    const hash = await hashEdwardsPublicKey(pubKey);

    expect(hash).toEqual(
      BigInt(
        "473788188026338532754827614266124932928610354793582188635738505121763471517"
      )
    );
  });

  test("poseidon reference is correct", async () => {
    const expected =
      "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a";
    const a = 1;
    const b = 2;

    const poseidon = await buildPoseidon();
    const hash = poseidon.F.toString(poseidon([a, b]), 16);

    expect(hash).toEqual(expected);
  });

  test("poseidon reference is correct 2", async () => {
    const expected =
      "473788188026338532754827614266124932928610354793582188635738505121763471517";
    const a =
      "11513997017404587999039986937421722453331811838930011493225155799998969860257";
    const b =
      "15702184800053625297652133943476286357553803483146409610785811576616213183541";

    const poseidon = await buildPoseidon();
    const hash = poseidon.F.toString(poseidon([a, b]), 10);

    expect(hash).toEqual(expected);
  });
});
