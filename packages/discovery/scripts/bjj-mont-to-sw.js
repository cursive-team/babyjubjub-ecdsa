const BN = require("bn.js");

// a = (3-A^2)/(3B^2) and b = (2A^3-9A)/(27B^3)

// Initialize big numbers
let A = new BN("168698", 10);
let B = new BN("1", 10);
let prime = new BN(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
  10
);
let two = new BN("2", 10);
let three = new BN("3", 10);
let tinv = three.invm(prime);

let a = three
  .sub(A.mul(A).mod(prime))
  .add(prime)
  .mod(prime)
  .mul(tinv)
  .mod(prime);

console.log("a", a.toString(16));

let b = two
  .mul(A.mul(A).mul(A))
  .sub(three.mul(three).mul(A))
  .mod(prime)
  .add(prime)
  .mod(prime)
  .mul(tinv)
  .mul(tinv)
  .mul(tinv)
  .mod(prime);

console.log("b", b.toString(16));

/**
 * a 10216f7ba065e00de81ac1e7808072c9b8114d6d7de87adb16a0a72f1a91f6a0
 * b 23d885f647fed5743cad3d1ee4aba9c043b4ac0fc2766658a410efdeb21f706e
 * */
