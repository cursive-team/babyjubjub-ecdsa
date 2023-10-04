import {
  privateKeyToPublicKey,
  recoverPubKeyIndexFromSignature,
  verifyEcdsaSignature,
} from "../src/ecdsa";
import { hexToBigInt } from "../src/utils";

describe("javascript signature verification", () => {
  test("should verify a baby jubjub ecdsa signature 0", () => {
    const privKey =
      "0323dbbda9a5aff570d974d71c88334cf99ab9c0455e1d2546ca03ca069eb1e0";
    const msgHash = BigInt("0");
    const sig = {
      r: hexToBigInt(
        "00EF7145470CEC0B683C629CBA8ED58110000FFE657366F7D5A91F2D149DD8B5"
      ),
      s: hexToBigInt(
        "0370C60A23266F520C56DA088B4C4AFAAAF6BB1993A501980F6D8FB6F343984A"
      ),
    };

    const pubKey = privateKeyToPublicKey(hexToBigInt(privKey));

    expect(verifyEcdsaSignature(sig, msgHash, pubKey)).toBe(true);
  });

  test("should verify a baby jubjub ecdsa signature 1", () => {
    const privKey =
      "0323dbbda9a5aff570d974d71c88334cf99ab9c0455e1d2546ca03ca069eb1e0";
    const msgHash = BigInt("1");
    const sig = {
      r: hexToBigInt(
        "04BEF5B82A7637BBFF0D3C52DDB982A00C84FE8A386625369B511CF538CD3584"
      ),
      s: hexToBigInt(
        "00CA8ED01E70CEC6DE27C1B9F6735B52FB49E4521F50BEEDEED8E81459729E2E"
      ),
    };

    const pubKey = privateKeyToPublicKey(hexToBigInt(privKey));

    expect(verifyEcdsaSignature(sig, msgHash, pubKey)).toBe(true);
  });

  test("should verify a baby jubjub ecdsa signature 2", () => {
    const privKey =
      "0323dbbda9a5aff570d974d71c88334cf99ab9c0455e1d2546ca03ca069eb1e0";
    const msgHash = BigInt("2");
    const sig = {
      r: hexToBigInt(
        "05718D88F4B6B357D2D9D53708F1C3EFE61C38C6A8BD107B2779182D80E75665"
      ),
      s: hexToBigInt(
        "00906FA5864D2682981DA3B5BABBB5C3EA07E008335ED8266C55546D46B45A42"
      ),
    };

    const pubKey = privateKeyToPublicKey(hexToBigInt(privKey));

    expect(verifyEcdsaSignature(sig, msgHash, pubKey)).toBe(true);
  });
});

describe("ecdsa public key recovery", () => {
  it("should recover the correct public key index", () => {
    const pubKeys = [
      "041941f5abe4f903af965d707182b688bd1fa725fd2cbc648fc435feb42a3794593275a2e9b4ad4bc0d2f3ecc8d23e3cf89da889d7aa35ce33f132d87b5bb5c393",
      "049ae9f2ec6a4db43f0e081a436f885b0d3f5753a45b00d2f2e3da38956848c4ff0205d89e14a2e36976bfe033407dbce6b48261d84d201277de0c3b82f08ddb09",
      "041052d6da0c3d7248e39e08912e2daa53c4e54cd9f2d96e3702fa15e77b199a501cd835bbddcc77134dc59dbbde2aa702183a68c90877906a31536eef972fac36",
      "044d9d03f3266f24777ac488f04ec579e1c4bea984398c9b98d99a9e31bc75ef0f13a19471a7297a6f2bf0126ed93d4c55b6e98ec286203e3d761c61922e3a4cda",
    ];
    const msgHash = BigInt("0");
    const sig = {
      r: hexToBigInt(
        "00EF7145470CEC0B683C629CBA8ED58110000FFE657366F7D5A91F2D149DD8B5"
      ),
      s: hexToBigInt(
        "0370C60A23266F520C56DA088B4C4AFAAAF6BB1993A501980F6D8FB6F343984A"
      ),
    };

    const recoveredIndex = recoverPubKeyIndexFromSignature(
      sig,
      msgHash,
      pubKeys
    );

    const expectedIndex = 2;

    expect(recoveredIndex).toEqual(expectedIndex);
  });
});
