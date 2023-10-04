import {
  getPublicInputsFromSignature,
  privateKeyToPublicKey,
} from "../src/witness";
import {
  hashEdwardsPublicKey,
  hexToBigInt,
  publicKeyFromString,
} from "../src/sig";
import { verifyEcdsaSignature } from "../src/witness";
import { EdwardsPoint, WeierstrassPoint } from "../src/babyJubjub";
import { buildPoseidon } from "circomlibjs";

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

describe("membership proof input generation", () => {
  test("should generate the correct membership proof inputs 0", () => {
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

    expect(getPublicInputsFromSignature(sig, msgHash, pubKey)).toEqual(
      expectedPublicInputs
    );
  });

  test("should generate the correct membership proof inputs 1", () => {
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

    const expectedPublicInputs = {
      T: new EdwardsPoint(
        BigInt(
          "11049791236506940775725016544774320801686704107093911375737399460678915074436"
        ),
        BigInt(
          "14122061015030538160275787174689078850141853547608413074819581224165574773574"
        )
      ),
      U: new EdwardsPoint(
        BigInt(
          "17661096655543715863576137188167626017028246425310027807366088195279768131966"
        ),
        BigInt(
          "14373145511494387599713118740758989353719893153627927440414777115915318733458"
        )
      ),
    };

    expect(getPublicInputsFromSignature(sig, msgHash, pubKey)).toEqual(
      expectedPublicInputs
    );
  });

  test("should generate the correct membership proof inputs 2", () => {
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

    const expectedPublicInputs = {
      T: new EdwardsPoint(
        BigInt(
          "729098367187965354918943799695726574481877310930907216460139273627632312398"
        ),
        BigInt(
          "11600818071736327742435312897539869536517700079344068315816316638597500129158"
        )
      ),
      U: new EdwardsPoint(
        BigInt(
          "13434541493412593418960175739314119796705787148870284412197696617048212434250"
        ),
        BigInt(
          "9218166335139589039436864178991191913089775550779587671062792149986059673719"
        )
      ),
    };

    expect(getPublicInputsFromSignature(sig, msgHash, pubKey)).toEqual(
      expectedPublicInputs
    );
  });
});

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
