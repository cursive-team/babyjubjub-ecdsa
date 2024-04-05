const fs = require("fs");
// @ts-ignore
import { buildPoseidonReference as buildPoseidon } from "circomlibjs";
import { batchProveMembership, proveMembership } from "../src/prove";
import {
  batchVerifyMembership,
  getPublicSignalsFromMembershipZKP,
  verifyMembership,
  verifyMembershipZKP,
} from "../src/verify";
import {
  derDecodeSignature,
  hashEdwardsPublicKey,
  hexToBigInt,
  publicKeyFromString,
} from "../src/utils";
import { EdwardsPoint, WeierstrassPoint } from "../src/babyJubjub";
import {
  computeMerkleProof,
  computeMerkleRoot,
  getPublicInputsFromSignature,
} from "../src/inputGen";

// Tests membership proof generation and verification, including zkp proving and verification
describe("ECDSA membership proof generation and verification", () => {
  afterAll(async () => {
    // snarkjs will not terminate this object automatically
    // We should do so after all proving/verification is finished for caching purposes
    // See: https://github.com/iden3/snarkjs/issues/152
    // @ts-ignore
    await globalThis.curve_bn128.terminate();
  });

  const MERKLE_TREE_DEPTH = 8;
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
    const sigNullifierRandomness = BigInt(0);
    const pubKeyNullifierRandomness = BigInt(0);

    test("should generate and verify a membership proof and return the correct nullifier", async () => {
      const msgHash = BigInt("0");
      const sig = {
        r: hexToBigInt(
          "00EF7145470CEC0B683C629CBA8ED58110000FFE657366F7D5A91F2D149DD8B5"
        ),
        s: hexToBigInt(
          "0370C60A23266F520C56DA088B4C4AFAAAF6BB1993A501980F6D8FB6F343984A"
        ),
      };
      const poseidon = await buildPoseidon();

      const proof = await proveMembership({
        sig,
        msgHash,
        merkleTreeDepth: MERKLE_TREE_DEPTH,
        merkleProofArgs: {
          pubKeys: pubKeyPoints,
          index: 2,
          hashFn: poseidon,
        },
        sigNullifierRandomness,
        pubKeyNullifierRandomness,
        pathToCircuits,
      });

      const result = await verifyMembership({
        proof,
        merkleTreeDepth: MERKLE_TREE_DEPTH,
        merkleRootArgs: {
          pubKeys: pubKeyPoints,
          hashFn: poseidon,
        },
        sigNullifierRandomness,
        pathToCircuits,
      });

      const expectedSigNullifier = hexToBigInt(
        poseidon.F.toString(poseidon([sig.s, sigNullifierRandomness]), 16)
      );

      expect(result.verified).toBe(true);
      expect(result.consumedSigNullifiers).toEqual([expectedSigNullifier]);
    });

    test("should generate and a valid membership proof with precomputed inputs", async () => {
      const msgHash = BigInt("0");
      const sig = {
        r: hexToBigInt(
          "00EF7145470CEC0B683C629CBA8ED58110000FFE657366F7D5A91F2D149DD8B5"
        ),
        s: hexToBigInt(
          "0370C60A23266F520C56DA088B4C4AFAAAF6BB1993A501980F6D8FB6F343984A"
        ),
      };
      const index = 2;

      const pubKeyPoints = pubKeys.map(publicKeyFromString);

      const publicInputs = getPublicInputsFromSignature(
        sig,
        msgHash,
        pubKeyPoints[index]
      );

      const edwardsPubKeys = await Promise.all(
        pubKeyPoints.map(async (pubKey) => pubKey.toEdwards())
      );
      const merkleProof = await computeMerkleProof(
        MERKLE_TREE_DEPTH,
        edwardsPubKeys,
        index
      );

      const proof = await proveMembership({
        sig,
        msgHash,
        publicInputs,
        merkleTreeDepth: MERKLE_TREE_DEPTH,
        merkleProof,
        sigNullifierRandomness,
        pubKeyNullifierRandomness,
        pathToCircuits,
      });

      const result = await verifyMembership({
        proof,
        merkleTreeDepth: MERKLE_TREE_DEPTH,
        merkleRootArgs: {
          pubKeys: pubKeyPoints,
        },
        sigNullifierRandomness,
        pathToCircuits,
      });

      expect(result.verified).toBe(true);
    });

    test("should generate and verify a membership proof with precomputed inputs", async () => {
      const msgHash = BigInt("0");
      const sig = {
        r: hexToBigInt(
          "00EF7145470CEC0B683C629CBA8ED58110000FFE657366F7D5A91F2D149DD8B5"
        ),
        s: hexToBigInt(
          "0370C60A23266F520C56DA088B4C4AFAAAF6BB1993A501980F6D8FB6F343984A"
        ),
      };
      const index = 2;

      const pubKeyPoints = pubKeys.map(publicKeyFromString);

      const publicInputs = getPublicInputsFromSignature(
        sig,
        msgHash,
        pubKeyPoints[index]
      );

      const edwardsPubKeys = await Promise.all(
        pubKeyPoints.map(async (pubKey) => pubKey.toEdwards())
      );
      const merkleProof = await computeMerkleProof(
        MERKLE_TREE_DEPTH,
        edwardsPubKeys,
        index
      );
      const proof = await proveMembership({
        sig,
        msgHash,
        publicInputs,
        merkleTreeDepth: MERKLE_TREE_DEPTH,
        merkleProof,
        sigNullifierRandomness,
        pubKeyNullifierRandomness,
        pathToCircuits,
      });

      const merkleRoot = await computeMerkleRoot(
        MERKLE_TREE_DEPTH,
        edwardsPubKeys
      );
      const result = await verifyMembership({
        proof,
        merkleTreeDepth: MERKLE_TREE_DEPTH,
        merkleRoot,
        sigNullifierRandomness,
        pathToCircuits,
      });

      expect(result.verified).toBe(true);
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
    const sigNullifierRandomness = BigInt("420420420");
    const pubKeyNullifierRandomness = BigInt("13371337");

    test("should generate and verify a membership proof with encoded signatures and nullifier randomness 0", async () => {
      const encodedSig =
        "30440220036E3AD3E9358B8299A60150BB925DEF60519861DB29E6468366ABE441F04C71022003872AABF9BE3935EF255FDB847A09E1789990BE85C3C368589D7693D0E5B36F";
      const sig = derDecodeSignature(encodedSig);

      const proof = await proveMembership({
        sig,
        msgHash,
        merkleTreeDepth: MERKLE_TREE_DEPTH,
        merkleProofArgs: {
          pubKeys,
          index: 1,
        },
        sigNullifierRandomness,
        pubKeyNullifierRandomness,
        pathToCircuits,
      });

      const result = await verifyMembership({
        proof,
        merkleTreeDepth: MERKLE_TREE_DEPTH,
        merkleRootArgs: {
          pubKeys,
        },
        sigNullifierRandomness,
        pathToCircuits,
      });

      expect(result.verified).toBe(true);
    });

    test("should generate and verify a membership proof with encoded signatures and nullifier randomness 1", async () => {
      const encodedSig =
        "30440220050AFA65DFD6E8709364DCF739FBAF2D6B436F84ADD5296BEE38BC65FA116912022001E8390CB9EF3688E2F319C0D08BB5DC11442BA9A93453660CD86B3728D0C106";
      const sig = derDecodeSignature(encodedSig);

      const proof = await proveMembership({
        sig,
        msgHash,
        merkleTreeDepth: MERKLE_TREE_DEPTH,
        merkleProofArgs: {
          pubKeys,
          index: 2,
        },
        sigNullifierRandomness,
        pubKeyNullifierRandomness,
        pathToCircuits,
      });

      const result = await verifyMembership({
        proof,
        merkleTreeDepth: MERKLE_TREE_DEPTH,
        merkleRootArgs: {
          pubKeys,
        },
        sigNullifierRandomness,
        pathToCircuits,
      });

      expect(result.verified).toBe(true);
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
      const sigs = encodedSigs.map(derDecodeSignature);

      const proofs = await batchProveMembership({
        sigs,
        msgHashes: [msgHash, msgHash, msgHash, msgHash, msgHash, msgHash],
        merkleTreeDepth: MERKLE_TREE_DEPTH,
        merkleProofArgs: {
          pubKeys,
          indices: [1, 1, 2, 2, 3, 3],
        },
        sigNullifierRandomness,
        pubKeyNullifierRandomness,
        pathToCircuits,
      });

      const result = await batchVerifyMembership({
        proofs,
        merkleTreeDepth: MERKLE_TREE_DEPTH,
        merkleRootArgs: {
          pubKeys,
        },
        sigNullifierRandomness,
        pathToCircuits,
      });

      expect(result.verified).toBe(true);
    });
  });

  // Tests recovery of public signals from membership proof
  describe("recover public signals from membership proof", () => {
    test("should recover the correct public signals from a generated proof", async () => {
      const pubKeys = [
        "041941f5abe4f903af965d707182b688bd1fa725fd2cbc648fc435feb42a3794593275a2e9b4ad4bc0d2f3ecc8d23e3cf89da889d7aa35ce33f132d87b5bb5c393",
        "049ae9f2ec6a4db43f0e081a436f885b0d3f5753a45b00d2f2e3da38956848c4ff0205d89e14a2e36976bfe033407dbce6b48261d84d201277de0c3b82f08ddb09",
        "041052d6da0c3d7248e39e08912e2daa53c4e54cd9f2d96e3702fa15e77b199a501cd835bbddcc77134dc59dbbde2aa702183a68c90877906a31536eef972fac36",
        "044d9d03f3266f24777ac488f04ec579e1c4bea984398c9b98d99a9e31bc75ef0f13a19471a7297a6f2bf0126ed93d4c55b6e98ec286203e3d761c61922e3a4cda",
      ];
      const pubKeyPoints = pubKeys.map(publicKeyFromString);
      const sigNullifierRandomness = BigInt(0);
      const pubKeyNullifierRandomness = BigInt(0);
      const index = 2;
      const msgHash = BigInt("0");
      const sig = {
        r: hexToBigInt(
          "00EF7145470CEC0B683C629CBA8ED58110000FFE657366F7D5A91F2D149DD8B5"
        ),
        s: hexToBigInt(
          "0370C60A23266F520C56DA088B4C4AFAAAF6BB1993A501980F6D8FB6F343984A"
        ),
      };
      const poseidon = await buildPoseidon();

      const proof = await proveMembership({
        sig,
        msgHash,
        merkleTreeDepth: MERKLE_TREE_DEPTH,
        merkleProofArgs: {
          pubKeys: pubKeyPoints,
          index,
        },
        sigNullifierRandomness,
        pubKeyNullifierRandomness,
        pathToCircuits,
      });

      const expectedSigNullifier = hexToBigInt(
        poseidon.F.toString(poseidon([sig.s, sigNullifierRandomness]), 16)
      );
      const pubKey = pubKeyPoints[index];
      const pubKeyHash = await hashEdwardsPublicKey(
        pubKey.toEdwards(),
        poseidon
      );
      const expectedPubKeyNullifier = hexToBigInt(
        poseidon.F.toString(
          poseidon([pubKeyHash, pubKeyNullifierRandomness]),
          16
        )
      );
      const expectedPubKeyNullifierRandomnessHash = hexToBigInt(
        poseidon.F.toString(poseidon([pubKeyNullifierRandomness]), 16)
      );

      const publicSignals = getPublicSignalsFromMembershipZKP(proof.zkp);

      expect(publicSignals.sigNullifier).toEqual(expectedSigNullifier);
      expect(publicSignals.pubKeyNullifier).toEqual(expectedPubKeyNullifier);
      expect(publicSignals.pubKeyNullifierRandomnessHash).toEqual(
        expectedPubKeyNullifierRandomnessHash
      );
      // Precomputed values from Python implementation
      expect(publicSignals.merkleRoot).toEqual(
        BigInt(
          "1799182282238172949735919814155076722550339245418717182904975644657694908682"
        )
      );
      expect(
        publicSignals.T.equals(
          new EdwardsPoint(
            BigInt(
              "11796026433945242671642728009981778919257130899633207712788256867701213124641"
            ),
            BigInt(
              "14123514812924309349601388555201142092835117152213858542018278815110993732603"
            )
          )
        )
      ).toBe(true);
      expect(
        publicSignals.U.equals(new EdwardsPoint(BigInt("0"), BigInt("1")))
      ).toBe(true);
      expect(publicSignals.sigNullifierRandomness).toEqual(
        sigNullifierRandomness
      );
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
