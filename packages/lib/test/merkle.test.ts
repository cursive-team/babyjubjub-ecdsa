import { buildPoseidon } from "circomlibjs";
import { generateMerkleProof } from "../src/merkle";
import {
  hashEdwardsPublicKey,
  hexToBigInt,
  publicKeyFromString,
} from "../src/sig";

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
