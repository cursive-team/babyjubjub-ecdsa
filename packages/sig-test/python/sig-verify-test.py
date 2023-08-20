from ecdsa import ellipticcurve, numbertheory, ecdsa, SigningKey, VerifyingKey, curves
from ecdsa.util import string_to_number, number_to_string, sigdecode_string

# Define the custom short Weierstrass curve parameters
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
a = 0x10216f7ba065e00de81ac1e7808072c9b8114d6d7de87adb16a0a72f1a91f6a0
b = 0x23d885f647fed5743cad3d1ee4aba9c043b4ac0fc2766658a410efdeb21f706e
Gx = 0x1fde0a3cac7cb46b36c79f4c0a7a732e38c2c7ee9ac41f44392a07b748a0869f
Gy = 0x203a710160811d5c07ebaeb8fe1d9ce201c66b970d66f18d0d2b264c195309aa
order = 0x60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1

# Check p is same as bn254 scalar field
# https://github.com/ethereum/EIPs/blob/master/EIPS/eip-197.md#definition-of-the-groups
print("Valid p?", p == 21888242871839275222246405745257275088548364400416034343698204186575808495617)

# Create the curve and generator point
curveFp = ellipticcurve.CurveFp(p, a, b)
generator = ellipticcurve.Point(curveFp, Gx, Gy, order=order)
curve = curves.Curve('babyjubjub', curveFp, generator, None)

# Given private key
priv_key_value = 0xabadbabeabadbabeabadbabeabadbabe
private_key = SigningKey.from_secret_exponent(priv_key_value, curve=curve)

# Compute the public key
public_key_point = priv_key_value * generator
print(public_key_point)

# null hash function
class HashOut:
  def digest(self):
    return bytes.fromhex("abadbabeabadbabeabadbabeabadbabe")

def hashfunc(data):
  return HashOut()

message = b"Hello, World!"
signature = private_key.sign(message, hashfunc=hashfunc)

r, s = sigdecode_string(signature, order)
print(f"Signature (r, s): ({hex(r)}, {hex(s)})")

# signature verification
verifying_key = VerifyingKey.from_public_point(public_key_point,
                                               curve=curve,
                                               hashfunc=hashfunc)

if verifying_key.verify(signature, message, hashfunc=hashfunc):
  print("Signature is valid!")
else:
  print("Signature is invalid!")
