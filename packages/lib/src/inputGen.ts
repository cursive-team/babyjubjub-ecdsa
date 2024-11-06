const BN = require("bn.js");
// @ts-ignore
import { buildPoseidonReference as buildPoseidon } from "circomlibjs";
import { EdwardsPoint, WeierstrassPoint, babyjubjub } from "./babyJubjub";
import { Signature, MerkleProof } from "./types";
import { hashEdwardsPublicKey, hexToBigInt } from "./utils";

export const MAX_MERKLE_TREE_DEPTH = 30; // Limit on depth of merkle tree
// Precomputed hashes of zero for each layer of the merkle tree
export const MERKLE_TREE_ZEROS = [
  "0",
  "14744269619966411208579211824598458697587494354926760081771325075741142829156",
  "7423237065226347324353380772367382631490014989348495481811164164159255474657",
  "11286972368698509976183087595462810875513684078608517520839298933882497716792",
  "3607627140608796879659380071776844901612302623152076817094415224584923813162",
  "19712377064642672829441595136074946683621277828620209496774504837737984048981",
  "20775607673010627194014556968476266066927294572720319469184847051418138353016",
  "3396914609616007258851405644437304192397291162432396347162513310381425243293",
  "21551820661461729022865262380882070649935529853313286572328683688269863701601",
  "6573136701248752079028194407151022595060682063033565181951145966236778420039",
  "12413880268183407374852357075976609371175688755676981206018884971008854919922",
  "14271763308400718165336499097156975241954733520325982997864342600795471836726",
  "20066985985293572387227381049700832219069292839614107140851619262827735677018",
  "9394776414966240069580838672673694685292165040808226440647796406499139370960",
  "11331146992410411304059858900317123658895005918277453009197229807340014528524",
  "15819538789928229930262697811477882737253464456578333862691129291651619515538",
  "19217088683336594659449020493828377907203207941212636669271704950158751593251",
  "21035245323335827719745544373081896983162834604456827698288649288827293579666",
  "6939770416153240137322503476966641397417391950902474480970945462551409848591",
  "10941962436777715901943463195175331263348098796018438960955633645115732864202",
  "15019797232609675441998260052101280400536945603062888308240081994073687793470",
  "11702828337982203149177882813338547876343922920234831094975924378932809409969",
  "11217067736778784455593535811108456786943573747466706329920902520905755780395",
  "16072238744996205792852194127671441602062027943016727953216607508365787157389",
  "17681057402012993898104192736393849603097507831571622013521167331642182653248",
  "21694045479371014653083846597424257852691458318143380497809004364947786214945",
  "8163447297445169709687354538480474434591144168767135863541048304198280615192",
  "14081762237856300239452543304351251708585712948734528663957353575674639038357",
  "16619959921569409661790279042024627172199214148318086837362003702249041851090",
  "7022159125197495734384997711896547675021391130223237843255817587255104160365",
  "4114686047564160449611603615418567457008101555090703535405891656262658644463",
];

/**
 * Computes the merkle root based a list of public keys
 * Note that public keys must be in Twisted Edwards form
 * This is because we only ever use the Merkle Tree for in circuit verification,
 * and the circuit only ever uses Twisted Edwards points
 * @param merkleTreeDepth - The depth of the merkle tree to generate the proof for
 * @param pubKeys - The list of public keys to compute the merkle root of in Twisted Edwards form
 * @param hashFn - The hash function to use for the merkle tree. Defaults to Poseidon
 * @returns - The merkle root
 */
export const computeMerkleRoot = async (
  merkleTreeDepth: number,
  pubKeys: EdwardsPoint[],
  hashFn?: any
): Promise<bigint> => {
  const proof = await computeMerkleProof(merkleTreeDepth, pubKeys, 0, hashFn);
  return proof.root;
};

/**
 * Generates a merkle proof for a given list of public keys and index
 * Once again, all public keys are represented in Twisted Edwards form
 * @param merkleTreeDepth - The depth of the merkle tree to generate the proof for
 * @param pubKeys - The list of public keys to generate the merkle proof for in Twisted Edwards form
 * @param index - The index of the public key to generate the merkle proof for
 * @param hashFn - The hash function to use for the merkle tree. Defaults to Poseidon
 * @returns - The merkle proof
 */
export const computeMerkleProof = async (
  merkleTreeDepth: number,
  pubKeys: EdwardsPoint[],
  index: number,
  hashFn?: any
): Promise<MerkleProof> => {
  // Merkle tree depth must be an integer between 1 and MAX_MERKLE_TREE_DEPTH
  if (
    !Number.isInteger(merkleTreeDepth) ||
    merkleTreeDepth < 1 ||
    merkleTreeDepth > MAX_MERKLE_TREE_DEPTH
  ) {
    throw new Error(
      `merkleTreeDepth must be an integer between 1 and ${MAX_MERKLE_TREE_DEPTH}`
    );
  }

  // Building poseidon actually takes a while, so it's best if it is passed in for client side proving
  const poseidon = hashFn === undefined ? await buildPoseidon() : hashFn;

  // All public keys are hashed before insertion into the tree
  const leaves = await Promise.all(
    pubKeys.map((pubKey) => hashEdwardsPublicKey(pubKey, poseidon))
  );

  let prevLayer: bigint[] = leaves;
  let nextLayer: bigint[] = [];
  let pathIndices: number[] = [];
  let siblings: bigint[] = [];

  for (let i = 0; i < merkleTreeDepth; i++) {
    pathIndices.push(index % 2);
    const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
    const sibling =
      siblingIndex === prevLayer.length
        ? BigInt(MERKLE_TREE_ZEROS[i])
        : prevLayer[siblingIndex];
    siblings.push(sibling);
    index = Math.floor(index / 2);

    for (let j = 0; j < prevLayer.length; j += 2) {
      const secondNode =
        j + 1 === prevLayer.length
          ? BigInt(MERKLE_TREE_ZEROS[i])
          : prevLayer[j + 1];
      const nextNode = poseidon([prevLayer[j], secondNode]);
      nextLayer.push(hexToBigInt(poseidon.F.toString(nextNode, 16)));
    }

    prevLayer = nextLayer;
    nextLayer = [];
  }
  const root = prevLayer[0];

  return { root, pathIndices, siblings: siblings };
};

/**
 * Generates the public inputs for a membership proof
 * Uses notation and formulation from Efficient ECDSA
 * https://personaelabs.org/posts/efficient-ecdsa-1/
 * Public inputs are points in Twisted Edwards form for efficient in circuit operations
 * @param sig - The signature to generate the public inputs for
 * @param msgHash - The message hash to generate the public inputs for
 * @param pubKey - The public key to generate the public inputs for
 * @throws If the public inputs cannot be found, i.e. R cannot be recovered from the signature
 * @returns - The public inputs R, T, U based on Efficient ECDSA format
 */
export const getPublicInputsFromSignature = (
  sig: Signature,
  msgHash: bigint,
  pubKey: WeierstrassPoint
): { R: EdwardsPoint; T: EdwardsPoint; U: EdwardsPoint } => {
  const Fb = babyjubjub.Fb;
  const Fs = babyjubjub.Fs;

  // Because the cofactor is > 1, we must check multiple points
  // See public key recovery algorithm: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
  for (let i = 0; i < babyjubjub.cofactor; i++) {
    console.log(i);
    for (const parity of [0, 1]) {
      const r = Fb.add(sig.r, Fb.mul(BigInt(i), Fs.p));
      const rInv = Fs.inv(r);
      let ecR;
      try {
        // The following will throw an error if the point is not on the curve
        ecR = babyjubjub.ec.curve.pointFromX(
          new BN(r.toString(16), 16),
          parity
        );
      } catch (e) {
        continue;
      }
      // We should use computeTUFromR here but I can't get the ec math to be correct from converting to elliptic.js points
      const ecT = ecR.mul(rInv.toString(16));
      const T = WeierstrassPoint.fromEllipticPoint(ecT);
      const G = babyjubjub.ec.curve.g;
      const rInvm = Fs.neg(Fs.mul(rInv, msgHash));
      const ecU = G.mul(rInvm.toString(16));
      const U = WeierstrassPoint.fromEllipticPoint(ecU);
      const sT = ecT.mul(sig.s.toString(16));
      const ecsTU = sT.add(ecU);
      const sTU = WeierstrassPoint.fromEllipticPoint(ecsTU);

      if (sTU.equals(pubKey)) {
        const R = WeierstrassPoint.fromEllipticPoint(ecR);
        return { R: R.toEdwards(), T: T.toEdwards(), U: U.toEdwards() };
      }
    }
  }

  throw new Error("Could not find valid public inputs");
};
