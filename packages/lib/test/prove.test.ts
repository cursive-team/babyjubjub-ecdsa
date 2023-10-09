const fs = require("fs");
import { batchProveMembership, proveMembership } from "../src/prove";
import {
  batchVerifyMembership,
  getNullifierFromMembershipProof,
  verifyMembership,
  verifyMembershipZKP,
} from "../src/verify";
import { derDecode, hexToBigInt, publicKeyFromString } from "../src/utils";
import { WeierstrassPoint } from "../src/babyJubjub";

// Tests membership proof generation and verification, including zkp proving and verification
describe("ECDSA membership proof generation and verification", () => {
  afterAll(async () => {
    // snarkjs will not terminate this object automatically
    // We should do so after all proving/verification is finished for caching purposes
    // See: https://github.com/iden3/snarkjs/issues/152
    // @ts-ignore
    await globalThis.curve_bn128.terminate();
  });

  const pathToCircuits = process.cwd() + "/test/circuits/";

  // Tests based on pre-generated BabyJubjub ECDSA signatures
  describe("generate and verify membership proofs", () => {
    const pubKeys = [
      "041941f5abe4f903af965d707182b688bd1fa725fd2cbc648fc435feb42a3794593275a2e9b4ad4bc0d2f3ecc8d23e3cf89da889d7aa35ce33f132d87b5bb5c393",
      "049ae9f2ec6a4db43f0e081a436f885b0d3f5753a45b00d2f2e3da38956848c4ff0205d89e14a2e36976bfe033407dbce6b48261d84d201277de0c3b82f08ddb09",
      "041052d6da0c3d7248e39e08912e2daa53c4e54cd9f2d96e3702fa15e77b199a501cd835bbddcc77134dc59dbbde2aa702183a68c90877906a31536eef972fac36",
      "044d9d03f3266f24777ac488f04ec579e1c4bea984398c9b98d99a9e31bc75ef0f13a19471a7297a6f2bf0126ed93d4c55b6e98ec286203e3d761c61922e3a4cda",
    ];
    const pubKeyPoints = pubKeys.map(publicKeyFromString);
    const nullifierRandomness = BigInt(0);

    test("should generate and verify a membership proof 0", async () => {
      const msgHash = BigInt("0");
      const sig = {
        r: hexToBigInt(
          "00EF7145470CEC0B683C629CBA8ED58110000FFE657366F7D5A91F2D149DD8B5"
        ),
        s: hexToBigInt(
          "0370C60A23266F520C56DA088B4C4AFAAAF6BB1993A501980F6D8FB6F343984A"
        ),
      };

      const proof = await proveMembership(
        sig,
        pubKeyPoints,
        2,
        msgHash,
        nullifierRandomness,
        pathToCircuits
      );

      const verified = await verifyMembership(
        proof,
        pubKeyPoints,
        nullifierRandomness,
        pathToCircuits
      );

      expect(verified).toBe(true);
    });
  });

  // Tests based on pre-generated BabyJubjub ECDSA signatures
  describe("generate and verify membership proofs with encoded signatures and nullifier randomness", () => {
    const pubKeys = [
      new WeierstrassPoint(
        BigInt(
          "7383369888919701441480368741745717804236448589785295824485316386504973064784"
        ),
        BigInt(
          "13046769583748125084667126323794391074141340611556711664428099286902963678262"
        )
      ),
      new WeierstrassPoint(
        BigInt(
          "8022836036792728510020073593790625374591718668941094754729876067757770684825"
        ),
        BigInt(
          "2888043282838146526405156459340757249954671046314727413645487686643973993965"
        )
      ),
      new WeierstrassPoint(
        BigInt(
          "9714024128310316092057230443118059995407288196097449837364797009977227758081"
        ),
        BigInt(
          "3986000760809817233522229217388333078261970153215912556094459527204210942908"
        )
      ),
      new WeierstrassPoint(
        BigInt(
          "7383369888919701441480368741745717804236448589785295824485316386504973064784"
        ),
        BigInt(
          "13046769583748125084667126323794391074141340611556711664428099286902963678262"
        )
      ),
    ];
    const msgHash = hexToBigInt(
      "00000000000000000000000000000000ABADBABEABADBABEABADBABEABADBABE"
    );
    const nullifierRandomness = BigInt("420420420");

    test("should generate and verify a membership proof with encoded signatures and nullifier randomness 0", async () => {
      const encodedSig =
        "30440220036E3AD3E9358B8299A60150BB925DEF60519861DB29E6468366ABE441F04C71022003872AABF9BE3935EF255FDB847A09E1789990BE85C3C368589D7693D0E5B36F";
      const sig = derDecode(encodedSig);

      const proof = await proveMembership(
        sig,
        pubKeys,
        1,
        msgHash,
        nullifierRandomness,
        pathToCircuits
      );

      const verified = await verifyMembership(
        proof,
        pubKeys,
        nullifierRandomness,
        pathToCircuits
      );

      expect(verified).toBe(true);
    });

    test("should generate and verify a membership proof with encoded signatures and nullifier randomness 1", async () => {
      const encodedSig =
        "30440220050AFA65DFD6E8709364DCF739FBAF2D6B436F84ADD5296BEE38BC65FA116912022001E8390CB9EF3688E2F319C0D08BB5DC11442BA9A93453660CD86B3728D0C106";
      const sig = derDecode(encodedSig);

      const proof = await proveMembership(
        sig,
        pubKeys,
        2,
        msgHash,
        nullifierRandomness,
        pathToCircuits
      );

      const verified = await verifyMembership(
        proof,
        pubKeys,
        nullifierRandomness,
        pathToCircuits
      );

      expect(verified).toBe(true);
    });

    test("should batch generate and verify membership proofs with encoded signatures and nullifier randomness", async () => {
      const encodedSigs = [
        "30440220036E3AD3E9358B8299A60150BB925DEF60519861DB29E6468366ABE441F04C71022003872AABF9BE3935EF255FDB847A09E1789990BE85C3C368589D7693D0E5B36F",
        "3044022001E82E797E53FB528D707B20513FC1B181A16315390DFC57FFCB477AC24A375E022004F7B2BCA543DEC95D6F82BC355C8E99F34DA07DE229B3A5D32999AB515F18E8",
        "30440220050AFA65DFD6E8709364DCF739FBAF2D6B436F84ADD5296BEE38BC65FA116912022001E8390CB9EF3688E2F319C0D08BB5DC11442BA9A93453660CD86B3728D0C106",
        "30440220014E817710DCA38B47415C0233C4FED1DA89D7195EC8F2FE1DEA9C72D378BC58022002E175D4810AB115BD7A52FB128BAF6319C2031FB991F665215564775CE8690D",
        "30440220017705D8D42EA7B179DCB1BB9ED1B37EB0F9A11DA2990E1B85C78D6C2132C46A0220021D258DFA097C255111C42DF04FC80572BE5E2173696FFF05A9B190A7C57FFA",
        "3044022001EA5ADC37063DC524E497A3A62D19A918519803FC7B041057D4CDD71579538C022003BD5A46DC348D1A1CA0AE424BF1011A517E2DA13562A083390F409E3C66B31B",
      ];
      const sigs = encodedSigs.map(derDecode);

      const proofs = await batchProveMembership(
        sigs,
        pubKeys,
        [1, 1, 2, 2, 3, 3],
        [msgHash, msgHash, msgHash, msgHash, msgHash, msgHash],
        nullifierRandomness,
        pathToCircuits
      );

      const verified = await batchVerifyMembership(
        proofs,
        pubKeys,
        nullifierRandomness,
        pathToCircuits
      );

      expect(verified).toBe(true);
    });
  });

  // Tests recovery of nullifier from membership proof
  describe("recover nullifier from proof", () => {
    test("should recover the correct nullifier", async () => {
      const pubKeys = [
        "041941f5abe4f903af965d707182b688bd1fa725fd2cbc648fc435feb42a3794593275a2e9b4ad4bc0d2f3ecc8d23e3cf89da889d7aa35ce33f132d87b5bb5c393",
        "049ae9f2ec6a4db43f0e081a436f885b0d3f5753a45b00d2f2e3da38956848c4ff0205d89e14a2e36976bfe033407dbce6b48261d84d201277de0c3b82f08ddb09",
        "041052d6da0c3d7248e39e08912e2daa53c4e54cd9f2d96e3702fa15e77b199a501cd835bbddcc77134dc59dbbde2aa702183a68c90877906a31536eef972fac36",
        "044d9d03f3266f24777ac488f04ec579e1c4bea984398c9b98d99a9e31bc75ef0f13a19471a7297a6f2bf0126ed93d4c55b6e98ec286203e3d761c61922e3a4cda",
      ];
      const pubKeyPoints = pubKeys.map(publicKeyFromString);
      const nullifierRandomness = BigInt(0);

      const msgHash = BigInt("0");
      const sig = {
        r: hexToBigInt(
          "00EF7145470CEC0B683C629CBA8ED58110000FFE657366F7D5A91F2D149DD8B5"
        ),
        s: hexToBigInt(
          "0370C60A23266F520C56DA088B4C4AFAAAF6BB1993A501980F6D8FB6F343984A"
        ),
      };

      const proof = await proveMembership(
        sig,
        pubKeyPoints,
        2,
        msgHash,
        nullifierRandomness,
        pathToCircuits
      );

      const recoveredNullifier = getNullifierFromMembershipProof(proof);

      const expectedNullifier = BigInt(
        "17825334909698573620993222371821585663772073121519814540615199066752100895281"
      );

      expect(recoveredNullifier).toEqual(expectedNullifier);
    });
  });

  describe("zero knowledge proof generation and verification", () => {
    test("should verify a zero knowledge proof generated by snarkjs", async () => {
      const vKey = JSON.parse(
        fs.readFileSync(pathToCircuits + "pubkey_membership_vkey.json")
      );
      const proof = JSON.parse(
        fs.readFileSync(pathToCircuits + "example_pubkey_membership_proof.json")
      );
      const publicSignals = JSON.parse(
        fs.readFileSync(
          pathToCircuits + "example_pubkey_membership_public.json"
        )
      );
      const zkp = {
        proof,
        publicSignals,
      };

      const verified = await verifyMembershipZKP(vKey, zkp);

      expect(verified).toBe(true);
    });
  });
});
