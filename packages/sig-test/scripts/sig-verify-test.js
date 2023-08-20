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
  g: {
    x: "0x1fde0a3cac7cb46b36c79f4c0a7a732e38c2c7ee9ac41f44392a07b748a0869f",
    y: "0x203a710160811d5c07ebaeb8fe1d9ce201c66b970d66f18d0d2b264c195309aa",
  },
  n: new BN(
    "2736030358979909402780800718157159386076813972158567259200215660948447373041",
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
console.log(keyPair);
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
