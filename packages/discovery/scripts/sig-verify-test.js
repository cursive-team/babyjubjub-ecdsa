const elliptic = require("elliptic");
const Signature = require("elliptic/lib/elliptic/ec/signature");
const hash = require("hash.js");
const derDecode = require("./der-decode");

// Define short Weierstrass parameters
const curveOptions = {
  p: "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
  prime: null,
  a: "10216f7ba065e00de81ac1e7808072c9b8114d6d7de87adb16a0a72f1a91f6a0",
  b: "23d885f647fed5743cad3d1ee4aba9c043b4ac0fc2766658a410efdeb21f706e",
  g: [
    "1fde0a3cac7cb46b36c79f4c0a7a732e38c2c7ee9ac41f44392a07b748a0869f",
    "203a710160811d5c07ebaeb8fe1d9ce201c66b970d66f18d0d2b264c195309aa",
  ],
  gRed: false,
  n: "60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1",
  type: "short",
};

// Create an elliptic curve with the defined parameters
const Short = elliptic.curve.short;
const curve = new Short(curveOptions);
const babyjubjub = new elliptic.ec({
  curve: { curve, g: curve.g, n: curve.n, hash: hash.sha256 },
});

// Generate a key pair for our provided private key (this is just for demonstration)
const privateKey = Buffer.from("abadbabeabadbabeabadbabeabadbabe", "hex");
const keyPair = babyjubjub.keyFromPrivate(privateKey);

const msgHash = Buffer.from("abadbabeabadbabeabadbabeabadbabe", "hex");
const sig = keyPair.sign(msgHash);
const verified = keyPair.verify(msgHash, sig);
console.log(verified);

// Sign and verify another message
const msg = "deadbeef";
const entropy = [
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
  23, 24, 25,
];
keys = babyjubjub.genKeyPair({
  entropy: entropy,
});
const signature = babyjubjub.sign(msg, keys);
console.log(babyjubjub.verify(msg, signature, keys));

// Verify example signatures
const examples = [
  {
    privateKey:
      "0323dbbda9a5aff570d974d71c88334cf99ab9c0455e1d2546ca03ca069eb1e0",
    message: "0",
    signature: {
      r: "00EF7145470CEC0B683C629CBA8ED58110000FFE657366F7D5A91F2D149DD8B5",
      s: "0370C60A23266F520C56DA088B4C4AFAAAF6BB1993A501980F6D8FB6F343984A",
    },
  },
  {
    privateKey:
      "0323dbbda9a5aff570d974d71c88334cf99ab9c0455e1d2546ca03ca069eb1e0",
    message: "1",
    signature: {
      r: "04BEF5B82A7637BBFF0D3C52DDB982A00C84FE8A386625369B511CF538CD3584",
      s: "00CA8ED01E70CEC6DE27C1B9F6735B52FB49E4521F50BEEDEED8E81459729E2E",
    },
  },
  {
    privateKey:
      "0323dbbda9a5aff570d974d71c88334cf99ab9c0455e1d2546ca03ca069eb1e0",
    message: "2",
    signature: {
      r: "05718D88F4B6B357D2D9D53708F1C3EFE61C38C6A8BD107B2779182D80E75665",
      s: "00906FA5864D2682981DA3B5BABBB5C3EA07E008335ED8266C55546D46B45A42",
    },
  },
];

for (const { privateKey, message, signature } of examples) {
  const newKeyPair = babyjubjub.keyFromPrivate(privateKey, "hex");

  const newMsg = message;
  const newSignature = new Signature(signature);
  console.log(babyjubjub.verify(newMsg, newSignature, newKeyPair));
}

// Verify DER encoded signatures
const derExamples = [
  {
    privateKey:
      "04b81e7180cd9504ce1bf0f728b4c828ad369781986aff07284d60ec1d59850b",
    message: "00000000000000000000000000000000ABADBABEABADBABEABADBABEABADBABE",
    encodedSignature:
      "30440220036E3AD3E9358B8299A60150BB925DEF60519861DB29E6468366ABE441F04C71022003872AABF9BE3935EF255FDB847A09E1789990BE85C3C368589D7693D0E5B36F",
  },
  {
    privateKey:
      "04b81e7180cd9504ce1bf0f728b4c828ad369781986aff07284d60ec1d59850b",
    message: "00000000000000000000000000000000ABADBABEABADBABEABADBABEABADBABE",
    encodedSignature:
      "3044022001E82E797E53FB528D707B20513FC1B181A16315390DFC57FFCB477AC24A375E022004F7B2BCA543DEC95D6F82BC355C8E99F34DA07DE229B3A5D32999AB515F18E8",
  },
  {
    privateKey:
      "02ea6ba4d6ec9b1b724f93a5ddf4ddcc94fc09909753088c272970fe3c99c4d8",
    message: "00000000000000000000000000000000ABADBABEABADBABEABADBABEABADBABE",
    encodedSignature:
      "30440220050AFA65DFD6E8709364DCF739FBAF2D6B436F84ADD5296BEE38BC65FA116912022001E8390CB9EF3688E2F319C0D08BB5DC11442BA9A93453660CD86B3728D0C106",
  },
  {
    privateKey:
      "02ea6ba4d6ec9b1b724f93a5ddf4ddcc94fc09909753088c272970fe3c99c4d8",
    message: "00000000000000000000000000000000ABADBABEABADBABEABADBABEABADBABE",
    encodedSignature:
      "30440220014E817710DCA38B47415C0233C4FED1DA89D7195EC8F2FE1DEA9C72D378BC58022002E175D4810AB115BD7A52FB128BAF6319C2031FB991F665215564775CE8690D",
  },
  {
    privateKey:
      "0323dbbda9a5aff570d974d71c88334cf99ab9c0455e1d2546ca03ca069eb1e0",
    message: "00000000000000000000000000000000ABADBABEABADBABEABADBABEABADBABE",
    encodedSignature:
      "30440220017705D8D42EA7B179DCB1BB9ED1B37EB0F9A11DA2990E1B85C78D6C2132C46A0220021D258DFA097C255111C42DF04FC80572BE5E2173696FFF05A9B190A7C57FFA",
  },
  {
    privateKey:
      "0323dbbda9a5aff570d974d71c88334cf99ab9c0455e1d2546ca03ca069eb1e0",
    message: "00000000000000000000000000000000ABADBABEABADBABEABADBABEABADBABE",
    encodedSignature:
      "3044022001EA5ADC37063DC524E497A3A62D19A918519803FC7B041057D4CDD71579538C022003BD5A46DC348D1A1CA0AE424BF1011A517E2DA13562A083390F409E3C66B31B",
  },
];

for (const { privateKey, message, encodedSignature } of derExamples) {
  const { r, s } = derDecode(encodedSignature);
  const newKeyPair = babyjubjub.keyFromPrivate(privateKey, "hex");

  const newMsg = message;
  const newSignature = new Signature({ r, s });
  console.log(babyjubjub.verify(newMsg, newSignature, newKeyPair));
}
