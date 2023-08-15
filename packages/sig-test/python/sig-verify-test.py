from ecdsa import ellipticcurve, numbertheory, ecdsa, SigningKey, VerifyingKey, curves
from ecdsa.util import string_to_number, number_to_string

# Define the custom short Weierstrass curve parameters
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
a = 0x10216f7ba065e00de81ac1e7808072c9b8114d6d7de87adb16a0a72f1a91f6a0
b = 0x23d885f647fed5743cad3d1ee4aba9c043b4ac0fc2766658a410efdeb21f706e
Gx = 7296080957279758407415468581752425029516121466805344781232734728858602888112
Gy = 4258727773875940690362607550498304598101071202821725296872974770776423442226
order = 21888242871839275222246405745257275088614511777268538073601725287587578984328

# Create the curve and generator point
curveFp = ellipticcurve.CurveFp(p, a, b)
generator = ellipticcurve.Point(curveFp, Gx, Gy, order=order)
curve = curves.Curve('babyjubjub', curveFp, generator, None)

# Given private key
priv_key_value = 0xabadbabeabadbabeabadbabeabadbabe
private_key = SigningKey.from_secret_exponent(priv_key_value, curve=curve)

# null hash function
class HashOut:
  def digest(self):
    return bytes.fromhex("abadbabeabadbabeabadbabeabadbabe")

def hashfunc(data):
  return HashOut()

# Compute the public key
public_key_point = priv_key_value * generator
verifying_key = VerifyingKey.from_public_point(public_key_point,
                                               curve=curve,
                                               hashfunc=hashfunc)

# Sample message and signature (you'd typically have these from elsewhere)
message = b"Hello, World!"
signature = private_key.sign(message, entropy=None, hashfunc=hashfunc)

# Verify the signature
if verifying_key.verify(signature, message, hashfunc=hashfunc):
  print("Signature is valid!")
else:
  print("Signature is invalid!")
