import { buildPoseidon } from "circomlibjs";
import {
  generateMerkleProof,
  getPublicInputsFromSignature,
} from "../src/inputGen";
import {
  hashEdwardsPublicKey,
  hexToBigInt,
  publicKeyFromString,
} from "../src/utils";
import { privateKeyToPublicKey } from "../src/ecdsa";
import { EdwardsPoint } from "../src/babyJubjub";

describe("merkle tree", () => {
  test("should generate the same merkle root as the circuit", async () => {
    const pubKeys = [
      "041941f5abe4f903af965d707182b688bd1fa725fd2cbc648fc435feb42a3794593275a2e9b4ad4bc0d2f3ecc8d23e3cf89da889d7aa35ce33f132d87b5bb5c393",
      "049ae9f2ec6a4db43f0e081a436f885b0d3f5753a45b00d2f2e3da38956848c4ff0205d89e14a2e36976bfe033407dbce6b48261d84d201277de0c3b82f08ddb09",
      "041052d6da0c3d7248e39e08912e2daa53c4e54cd9f2d96e3702fa15e77b199a501cd835bbddcc77134dc59dbbde2aa702183a68c90877906a31536eef972fac36",
      "044d9d03f3266f24777ac488f04ec579e1c4bea984398c9b98d99a9e31bc75ef0f13a19471a7297a6f2bf0126ed93d4c55b6e98ec286203e3d761c61922e3a4cda",
    ];
    const index = 2;
    const poseidon = await buildPoseidon();

    const merkleProof = await generateMerkleProof(pubKeys, index);

    const pubKey = pubKeys[index];
    const pubKeyWeierstrass = publicKeyFromString(pubKey);
    const pubKeyEdwards = pubKeyWeierstrass.toEdwards();
    const leaf = await hashEdwardsPublicKey(pubKeyEdwards);

    let node = leaf;
    for (let i = 0; i < 10; i++) {
      const otherNode = merkleProof.siblings[i];
      if (merkleProof.pathIndices[i] % 2 === 0) {
        node = poseidon([node, otherNode]);
      } else {
        node = poseidon([otherNode, node]);
      }
      node = hexToBigInt(poseidon.F.toString(node, 16));
    }

    const expectedRoot = BigInt(
      "4634016523752195062014614389412713184983003254567244385609775692869553859565"
    );

    expect(merkleProof.root).toEqual(expectedRoot);
    expect(node).toEqual(expectedRoot);
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
