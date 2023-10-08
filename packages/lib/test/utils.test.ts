import {
  bigIntToBytes,
  bigIntToHex,
  bytesToBigInt,
  bytesToHex,
  derDecode,
  hashEdwardsPublicKey,
  hexToBigInt,
  hexToBytes,
  publicKeyFromString,
} from "../src/utils";
import { EdwardsPoint, WeierstrassPoint } from "../src/babyJubjub";
// @ts-ignore
import { buildPoseidonReference } from "circomlibjs";

describe("signature and key parsing utilities", () => {
  test("should DER decode a signature 0", () => {
    const encodedSig =
      "30440220036E3AD3E9358B8299A60150BB925DEF60519861DB29E6468366ABE441F04C71022003872AABF9BE3935EF255FDB847A09E1789990BE85C3C368589D7693D0E5B36F";

    const expectedr = hexToBigInt(
      "036E3AD3E9358B8299A60150BB925DEF60519861DB29E6468366ABE441F04C71"
    );
    const expecteds = hexToBigInt(
      "03872AABF9BE3935EF255FDB847A09E1789990BE85C3C368589D7693D0E5B36F"
    );

    const parsedSig = derDecode(encodedSig);

    expect(parsedSig.r).toEqual(expectedr);
    expect(parsedSig.s).toEqual(expecteds);
  });

  test("should DER decode a signature 1", () => {
    const encodedSig =
      "3044022001E82E797E53FB528D707B20513FC1B181A16315390DFC57FFCB477AC24A375E022004F7B2BCA543DEC95D6F82BC355C8E99F34DA07DE229B3A5D32999AB515F18E8";

    const expectedr = hexToBigInt(
      "01E82E797E53FB528D707B20513FC1B181A16315390DFC57FFCB477AC24A375E"
    );
    const expecteds = hexToBigInt(
      "04F7B2BCA543DEC95D6F82BC355C8E99F34DA07DE229B3A5D32999AB515F18E8"
    );

    const parsedSig = derDecode(encodedSig);

    expect(parsedSig.r).toEqual(expectedr);
    expect(parsedSig.s).toEqual(expecteds);
  });

  test("should DER decode a signature 2", () => {
    const encodedSig =
      "30440220050AFA65DFD6E8709364DCF739FBAF2D6B436F84ADD5296BEE38BC65FA116912022001E8390CB9EF3688E2F319C0D08BB5DC11442BA9A93453660CD86B3728D0C106";

    const expectedr = hexToBigInt(
      "050AFA65DFD6E8709364DCF739FBAF2D6B436F84ADD5296BEE38BC65FA116912"
    );
    const expecteds = hexToBigInt(
      "01E8390CB9EF3688E2F319C0D08BB5DC11442BA9A93453660CD86B3728D0C106"
    );

    const parsedSig = derDecode(encodedSig);

    expect(parsedSig.r).toEqual(expectedr);
    expect(parsedSig.s).toEqual(expecteds);
  });

  test("should parse an encoded public key 0", () => {
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

  test("should parse an encoded public key 1", () => {
    const encodedPubKey =
      "0411bcc3a7bc7d083b6c67fc7fd33a31bafdfcbf8883dbbf1ab6fc3eba321c39990662931714e04b3a3deb0c6102d9bf7a7ac56ba7d281afc07afa803e65d9b5ed";

    const parsedPubKey = publicKeyFromString(encodedPubKey);

    const expectedPubKey = new WeierstrassPoint(
      BigInt(
        "8022836036792728510020073593790625374591718668941094754729876067757770684825"
      ),
      BigInt(
        "2888043282838146526405156459340757249954671046314727413645487686643973993965"
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

  test("poseidon reference is correct 0", async () => {
    const expected =
      "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a";
    const a = 1;
    const b = 2;

    const poseidon = await buildPoseidonReference();
    const hash = poseidon.F.toString(poseidon([a, b]), 16);

    expect(hash).toEqual(expected);
  });

  test("poseidon reference is correct 1", async () => {
    const expected =
      "473788188026338532754827614266124932928610354793582188635738505121763471517";
    const a =
      "11513997017404587999039986937421722453331811838930011493225155799998969860257";
    const b =
      "15702184800053625297652133943476286357553803483146409610785811576616213183541";

    const poseidon = await buildPoseidonReference();
    const hash = poseidon.F.toString(poseidon([a, b]), 10);

    expect(hash).toEqual(expected);
  });

  test("converts hex to bigint correctly", () => {
    const hex = "abcabcabcabc123456";
    const expected = BigInt("3169001976782843425878");

    expect(hexToBigInt(hex)).toEqual(expected);
  });

  test("converts bigint to hex correctly", () => {
    const bigInt = BigInt("3169001976782843425878");
    const expected = "abcabcabcabc123456";

    expect(bigIntToHex(bigInt)).toEqual(expected);
  });

  test("converts hex to bytes correctly", () => {
    const hex = "abcabcabcabc123456";
    const expected = Uint8Array.from([
      171, 202, 188, 171, 202, 188, 18, 52, 86,
    ]);

    expect(hexToBytes(hex)).toEqual(expected);
  });

  test("converts bytes to hex correctly", () => {
    const bytes = Uint8Array.from([171, 202, 188, 171, 202, 188, 18, 52, 86]);
    const expected = "abcabcabcabc123456";

    expect(bytesToHex(bytes)).toEqual(expected);
  });

  test("converts bytes to bigint correctly", () => {
    const bytes = Uint8Array.from([171, 202, 188, 171, 202, 188, 18, 52, 86]);
    const expected = BigInt("3169001976782843425878");

    expect(bytesToBigInt(bytes)).toEqual(expected);
  });

  test("converts bigint to bytes correctly", () => {
    const bigInt = BigInt("3169001976782843425878");
    const expected = Uint8Array.from([
      171, 202, 188, 171, 202, 188, 18, 52, 86,
    ]);

    expect(bigIntToBytes(bigInt)).toEqual(expected);
  });
});
