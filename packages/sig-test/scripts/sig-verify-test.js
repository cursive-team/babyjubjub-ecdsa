const elliptic = require("elliptic");
const BN = require("bn.js");

// Define short Weierstrass parameters
const curve = {
  p: new BN(
    "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    10
  ),
  a: "0x10216f7ba065e00de81ac1e7808072c9b8114d6d7de87adb16a0a72f1a91f6a0",
  b: "0x23d885f647fed5743cad3d1ee4aba9c043b4ac0fc2766658a410efdeb21f706e",
  g: [
    "7296080957279758407415468581752425029516121466805344781232734728858602888112",
    "4258727773875940690362607550498304598101071202821725296872974770776423442226",
  ],
  n: new BN(
    "21888242871839275222246405745257275088614511777268538073601725287587578984328",
    10
  ),
  h: "8",
  type: "short",
};

// convert p to hex
console.log("p", curve.p.toString("hex"));
console.log("n", curve.n.toString("hex"));

// Create an elliptic curve with the defined parameters
const babyjubjub = new elliptic.ec({ curve: { curve } });

// Generate a key pair for our provided private key (this is just for demonstration)
const privateKey = Buffer.from("abadbabeabadbabeabadbabeabadbabe", "hex");

// get keypair from public key (x,y)
const keyPair = babyjubjub.keyFromPrivate(privateKey);
const msgHash = Buffer.from("abadbabeabadbabeabadbabeabadbabe", "hex");

const signature = {
  r: new BN(
    "D47ADE8DCF5E8A8BD7EB3B3A73251489E5C70E45AA5DEFFDB56ACC23E52D5D9C",
    16
  ),
  s: new BN(
    "F401C2C2C1A98952FD14FE53E5B5B6D40BE6796FB772D224FECC56FAAF43C8A1",
    16
  ),
};

const isValidSignature = keyPair.verify(msgHash, signature);
console.log(isValidSignature ? "Valid signature" : "Invalid signature");

/* Manually computing signature verification */

// Calculate modular inverse of s
const sInv = signature.s.invm(babyjubjub.n);

// Calculate u1 and u2
const u1 = new BN("abadbabeabadbabeabadbabeabadbabe", 16)
  .mul(sInv)
  .umod(babyjubjub.n);
const u2 = signature.r.mul(sInv).umod(babyjubjub.n);

// print out u1 and u2 in decimal
console.log("u1", u1.toString(10));
console.log("u2", u2.toString(10));

// print out r in decimal
console.log("r", signature.r.toString(10));

// // Step 6: Calculate point (x, y)
// const pointU1 = babyjubjub.g.mul(u1);
// const pointU2 = keyPair.getPublic().mul(u2);
// const point = pointU1.add(pointU2);

// // Step 7: Calculate v
// const v = point.getX();

// // Step 8: Compare v and r
// const isSignatureValid = v.cmp(signature.r) === 0;

// console.log("Is signature valid?", isSignatureValid);
