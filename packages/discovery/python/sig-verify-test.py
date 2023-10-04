from ecdsa import ellipticcurve, SigningKey, curves
from ecdsa.util import sigdecode_string, sigencode_string

# null hash function
class HashOut:
  def digest(self):
    return bytes.fromhex("abadbabeabadbabeabadbabeabadbabe")

def hashfunc(data):
  return HashOut()

# Utility functions
def verify_sig(private_key, r, s):
  assert(r < order)
  assert(s < order)
  assert(int(private_key.to_string().hex(), 16) < order)

  message = bytes.fromhex("abadbabeabadbabeabadbabeabadbabe")
  signature = sigencode_string(r, s, order)
  verifying_key = private_key.get_verifying_key()

  return verifying_key.verify(signature, message, hashfunc=hashfunc)

def gen_sigs(private_key, num):
  sigs = []
  for i in range(0, num):
    message = bytes.fromhex("abadbabeabadbabeabadbabeabadbabe")
    signature = private_key.sign(message, hashfunc=hashfunc)
    r, s = sigdecode_string(signature, order)
    sigs.append((r, s))
  return sigs

# Define the custom short Weierstrass curve parameters
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
a = 0x10216f7ba065e00de81ac1e7808072c9b8114d6d7de87adb16a0a72f1a91f6a0
b = 0x23d885f647fed5743cad3d1ee4aba9c043b4ac0fc2766658a410efdeb21f706e
Gx = 0x1fde0a3cac7cb46b36c79f4c0a7a732e38c2c7ee9ac41f44392a07b748a0869f
Gy = 0x203a710160811d5c07ebaeb8fe1d9ce201c66b970d66f18d0d2b264c195309aa
order = 0x60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1

# Check p is same as bn254 scalar field
# https://github.com/ethereum/EIPs/blob/master/EIPS/eip-197.md#definition-of-the-groups
print("Curve validation")
print("Valid p?", p == 21888242871839275222246405745257275088548364400416034343698204186575808495617)
print()

# Create the curve and generator point
curveFp = ellipticcurve.CurveFp(p, a, b)
generator = ellipticcurve.Point(curveFp, Gx, Gy, order=order)
curve = curves.Curve('babyjubjub', curveFp, generator, None)

# code to randomly generate three valid private keys for this curve
print("Generate private keys")
for i in range(0, 3):
  private_key = SigningKey.generate(curve=curve)
  print(f'sk{i}', private_key.to_string().hex())
print()

# different private key options
random_private_key_value = 0x04031627028b95196e3bfe3b73c894d814dadedb20c6d7ed83e274c95e00bfc3
random_private_key = SigningKey.from_secret_exponent(random_private_key_value, curve=curve)

# Test generation and verification
print("Python signature verification")
sigs = gen_sigs(random_private_key, 10)
for r, s in sigs:
  print(r, s, verify_sig(random_private_key, r, s))
print()

# Output signatures for SAGE verification
print("Generating signatures for SAGE")
for r, s in sigs: 
  print("(" + str(hex(r)) + ", " + str(hex(s)) + "),")
print()

# Verify signatures from SAGE
print("SAGE signature verification")
SAGE_sigs = [
  (0xf5ce62892053e472b124009cfae18b6e209e5ffbc19388e1edfad5463c5ab6, 0x2dcde43ae510ced4d692fd32ac4f102fa683afbb6e28c0846429c4833e82e5b),
  (0x2987194b69fd63fcea4e0f5a164cb239803b043130d4f0e904354dd177bdb20, 0x4bade11ca631d9bf0db726fd0b540265c7c6ee8d8408a9dabf928b0c8311c88),
  (0x461ad46622561895587f24ce3d6d122ecb6feed919cb820f0c680b20a428c03, 0x13cfea0868c024d25f39a92041da39b9c42ef7b8d6dfdecd5c47bdbf3c6bb6e),
  (0x2dd71f92b1f175b6bb96f15aa78f2a5a8d24d6d0fd1ac41f8c307586c22d10e, 0x5c57eb6728a96bd0ce9be2ad763432d06c82954e5adad7245e88d5ec9f3cd5a),
  (0x126ca4d48acfdaeae0a6e25b501ec8ad6a7541c2dee919089c2e83edfd3ec7e, 0xe4e983000fcb8023dcf182d3bbf8033b817a9590f25c0836282c5ddd5e5b6),
  (0x12d9bfdb273a09101f8b1be3449ceca86286175431b146f0a5ba8b8d7c86d03, 0x252d4f52ae32718c7003ee23ed6a72a8e14bbfa9c1b8c12e8c440bad7e87128),
  (0x5915aadff8e99119b3a17f24349c5e204e09647a9d7de91b0da3e191a22eeb6, 0x1022c0ada14865c9bb1fc345db0425eff4184c5a71a9d5747cea7ed6676e31b),
  (0xd14891c77eafebf099c996f25266e60824830068110e6fb604470c0b67c314, 0x1cdd02a99404cc71d67daa5cec3c03d4304f6d3161f61131dc3b0e3e87b56dc),
  (0x3b1f03bfdb75de2ccf2471e9f8b85b0f67ca0b62598447a13c825c43abf92c, 0x3cca91632e85213396e5312ee3da3b46b9b96ef7696fcb15c84eb8885dc2a61),
  (0x11c8504a5b4462f7c3a5a1d93279ec49443de3d87ea9675cc44e39639df401f, 0x3121a4c5a7ae5b064709941c370b6b87c34e92a5492b7494267c7a759697f04)
]
for hex_r, hex_s in SAGE_sigs:
  print(hex_r, hex_s, verify_sig(random_private_key, hex_r, hex_s))
print()

print("Card message with padding signature verification")
card_first_sigs = [
  (0x02A043A728D9C86A5C82D0AA7455FC148EE2C91993325CBB307EB94D8434C39F, 0x02470171EEC9726D71F9CD194D876FC8762CA2BE1FF7B30ACD5DAF9762BE2438),
  (0x0579E805639DB82135A1A773B4C4A8861F236F1E343271DA0E1417AAF6345EDC, 0x026C3BC30E69019DD8C724680C812E9AC82214403198531B6B9556C745261268),
  (0x0041DCA2A8BF30D1B630A71702419F7BAFDCC8E1E417E8AD94379D74C0D161FD, 0x02FCAA7A8E69C21AA800A8FC259891CF98314FB68E5DC6A844FF5A568CCD779F)
]
for hex_r, hex_s in card_first_sigs:
  print(hex_r, hex_s, verify_sig(random_private_key, hex_r, hex_s))
print()