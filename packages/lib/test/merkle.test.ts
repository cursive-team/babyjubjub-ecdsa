import { buildPoseidon } from "circomlibjs";
import { generateMerkleProof } from "../src/lib";
import {
  bigIntToBytes,
  bytesToBigInt,
  hashEdwardsPublicKey,
  hashPublicKey,
  publicKeyFromString,
} from "../src/sig";

describe("merkle tree", () => {
  test("should generate a correct merkle tree", async () => {
    const pubKeys = [
      "041941f5abe4f903af965d707182b688bd1fa725fd2cbc648fc435feb42a3794593275a2e9b4ad4bc0d2f3ecc8d23e3cf89da889d7aa35ce33f132d87b5bb5c393",
      "049ae9f2ec6a4db43f0e081a436f885b0d3f5753a45b00d2f2e3da38956848c4ff0205d89e14a2e36976bfe033407dbce6b48261d84d201277de0c3b82f08ddb09",
      "041052d6da0c3d7248e39e08912e2daa53c4e54cd9f2d96e3702fa15e77b199a501cd835bbddcc77134dc59dbbde2aa702183a68c90877906a31536eef972fac36",
      "044d9d03f3266f24777ac488f04ec579e1c4bea984398c9b98d99a9e31bc75ef0f13a19471a7297a6f2bf0126ed93d4c55b6e98ec286203e3d761c61922e3a4cda",
      "041941f5abe4f903af965d707182b688bd1fa725fd2cbc648fc435feb42a3794593275a2e9b4ad4bc0d2f3ecc8d23e3cf89da889d7aa35ce33f132d87b5bb5c393",
      "049ae9f2ec6a4db43f0e081a436f885b0d3f5753a45b00d2f2e3da38956848c4ff0205d89e14a2e36976bfe033407dbce6b48261d84d201277de0c3b82f08ddb09",
      "041052d6da0c3d7248e39e08912e2daa53c4e54cd9f2d96e3702fa15e77b199a501cd835bbddcc77134dc59dbbde2aa702183a68c90877906a31536eef972fac36",
      "044d9d03f3266f24777ac488f04ec579e1c4bea984398c9b98d99a9e31bc75ef0f13a19471a7297a6f2bf0126ed93d4c55b6e98ec286203e3d761c61922e3a4cda",
    ];
    const index = 3;

    const proof = await generateMerkleProof(pubKeys, index);

    const merkleByHand = async (pubKeys: string[], index: number) => {
      const TREE_DEPTH = 10;
      const DEFAULT_VALUE = BigInt(0);
      const poseidon = await buildPoseidon();

      const leaves = await Promise.all(
        pubKeys.map((pubKey) => {
          const pubKeyWeierstrass = publicKeyFromString(pubKey);
          const pubKeyEdwards = pubKeyWeierstrass.toEdwards();
          return hashEdwardsPublicKey(pubKeyEdwards);
        })
      );
      for (let i = pubKeys.length; i < 2 ** TREE_DEPTH; i++) {
        leaves.push(bigIntToBytes(DEFAULT_VALUE));
      }

      const zeros: bigint[] = [DEFAULT_VALUE];
      let currZero = DEFAULT_VALUE;
      for (let i = 0; i < TREE_DEPTH; i += 1) {
        const nextZero = bytesToBigInt(
          poseidon([bigIntToBytes(currZero), bigIntToBytes(currZero)])
        );
        zeros.push(nextZero);
        currZero = nextZero;
      }

      let prevLayer: Uint8Array[] = leaves;
      let nextLayer: Uint8Array[] = [];
      let pathIndices: number[] = [];
      let siblings: Uint8Array[] = [];

      for (let i = 0; i < TREE_DEPTH; i++) {
        pathIndices.push(index % 2);
        const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
        siblings.push(prevLayer[siblingIndex]);
        index = Math.floor(index / 2);

        for (let j = 0; j < prevLayer.length; j += 2) {
          const nextNode = poseidon([prevLayer[j], prevLayer[j + 1]]);
          nextLayer.push(nextNode);
        }

        prevLayer = nextLayer;
        nextLayer = [];
      }

      const root = bytesToBigInt(prevLayer[0]);

      return { root, pathIndices, siblings: siblings.map(bytesToBigInt) };
    };

    const expectedProof = await merkleByHand(pubKeys, index);

    expect(proof.root).toBe(expectedProof.root);
    expect(proof.pathIndices).toEqual(expectedProof.pathIndices);
    expect(proof.siblings).toEqual(expectedProof.siblings);
  });
});
