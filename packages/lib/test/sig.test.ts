import {
  getPublicInputsFromSignature,
  privateKeyToPublicKey,
} from "../src/witness";
import { hexToBigInt } from "../src/sig";
import { verifyEcdsaSignature } from "../src/witness";
import { EdwardsPoint } from "../src/babyJubjub";

describe("javascript signature verification", () => {
  test("should verify a baby jubjub ecdsa signature 0", () => {
    const privKey =
      "0323dbbda9a5aff570d974d71c88334cf99ab9c0455e1d2546ca03ca069eb1e0";
    const msg = "0";
    const sig = {
      r: hexToBigInt(
        "00EF7145470CEC0B683C629CBA8ED58110000FFE657366F7D5A91F2D149DD8B5"
      ),
      s: hexToBigInt(
        "0370C60A23266F520C56DA088B4C4AFAAAF6BB1993A501980F6D8FB6F343984A"
      ),
    };

    const pubKey = privateKeyToPublicKey(hexToBigInt(privKey));

    expect(verifyEcdsaSignature(sig, msg, pubKey)).toBe(true);
  });

  test("should verify a baby jubjub ecdsa signature 1", () => {
    const privKey =
      "0323dbbda9a5aff570d974d71c88334cf99ab9c0455e1d2546ca03ca069eb1e0";
    const msg = "1";
    const sig = {
      r: hexToBigInt(
        "04BEF5B82A7637BBFF0D3C52DDB982A00C84FE8A386625369B511CF538CD3584"
      ),
      s: hexToBigInt(
        "00CA8ED01E70CEC6DE27C1B9F6735B52FB49E4521F50BEEDEED8E81459729E2E"
      ),
    };

    const pubKey = privateKeyToPublicKey(hexToBigInt(privKey));

    expect(verifyEcdsaSignature(sig, msg, pubKey)).toBe(true);
  });

  test("should verify a baby jubjub ecdsa signature 2", () => {
    const privKey =
      "0323dbbda9a5aff570d974d71c88334cf99ab9c0455e1d2546ca03ca069eb1e0";
    const msg = "2";
    const sig = {
      r: hexToBigInt(
        "05718D88F4B6B357D2D9D53708F1C3EFE61C38C6A8BD107B2779182D80E75665"
      ),
      s: hexToBigInt(
        "00906FA5864D2682981DA3B5BABBB5C3EA07E008335ED8266C55546D46B45A42"
      ),
    };

    const pubKey = privateKeyToPublicKey(hexToBigInt(privKey));

    expect(verifyEcdsaSignature(sig, msg, pubKey)).toBe(true);
  });
});

describe("membership proof input generation", () => {
  test("should generate the correct membership proof inputs 0", () => {
    const privKey =
      "0323dbbda9a5aff570d974d71c88334cf99ab9c0455e1d2546ca03ca069eb1e0";
    const msg = "0";
    const sig = {
      r: hexToBigInt(
        "00EF7145470CEC0B683C629CBA8ED58110000FFE657366F7D5A91F2D149DD8B5"
      ),
      s: hexToBigInt(
        "0370C60A23266F520C56DA088B4C4AFAAAF6BB1993A501980F6D8FB6F343984A"
      ),
    };

    const pubKey = privateKeyToPublicKey(hexToBigInt(privKey));

    const expectedPublicInputs = {
      T: new EdwardsPoint(
        BigInt(
          "11796026433945242671642728009981778919257130899633207712788256867701213124641"
        ),
        BigInt(
          "14123514812924309349601388555201142092835117152213858542018278815110993732603"
        )
      ),
      U: new EdwardsPoint(BigInt("0"), BigInt("1")),
    };

    expect(getPublicInputsFromSignature(sig, msg, pubKey)).toEqual(
      expectedPublicInputs
    );
  });
});
