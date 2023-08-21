from ecdsa import ellipticcurve, numbertheory, ecdsa, SigningKey, VerifyingKey, curves
from ecdsa.util import string_to_number, number_to_string, sigdecode_string, sigencode_string

# null hash function
class HashOut:
  def digest(self):
    return bytes.fromhex("00000000000000000000000000000000abadbabeabadbabeabadbabeabadbabe")

def hashfunc(data):
  return HashOut()

# Utility functions
def verify_sig(private_key, r, s):
  assert(r < order)
  assert(s < order)
  assert(int(private_key.to_string().hex(), 16) < order)

  message = bytes.fromhex("00000000000000000000000000000000abadbabeabadbabeabadbabeabadbabe")
  signature = sigencode_string(r, s, order)
  verifying_key = private_key.get_verifying_key()

  return verifying_key.verify(signature, message, hashfunc=hashfunc)

def gen_sigs(private_key, num):
  sigs = []
  for i in range(0, num):
    message = bytes.fromhex("00000000000000000000000000000000abadbabeabadbabeabadbabeabadbabe")
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

# Create the curve and generator point
curveFp = ellipticcurve.CurveFp(p, a, b)
generator = ellipticcurve.Point(curveFp, Gx, Gy, order=order)
curve = curves.Curve('babyjubjub', curveFp, generator, None)

# different private key options
random_private_key_value = 0x04031627028b95196e3bfe3b73c894d814dadedb20c6d7ed83e274c95e00bfc3
random_private_key = SigningKey.from_secret_exponent(random_private_key_value, curve=curve)

priv_key_value = 0x24abadbabeabadbabeabadbabeabadbabe
private_key = SigningKey.from_secret_exponent(priv_key_value, curve=curve)

# generate&verify sigs
sigs = gen_sigs(random_private_key, 10)
for r, s in sigs:
  print("(" + hex(r) + ", " + hex(s) + "),")
  assert verify_sig(random_private_key, r, s)

# verify_sig(random_private_key, 0x0579E805639DB82135A1A773B4C4A8861F236F1E343271DA0E1417AAF6345EDC, 0x026C3BC30E69019DD8C724680C812E9AC82214403198531B6B9556C745261268)