from ecdsa import ellipticcurve, SigningKey, curves
from ecdsa.util import sigencode_string

# null hash function
class HashOut:
  def digest(self):
    return bytes.fromhex("abadbabeabadbabeabadbabeabadbabe")

def hashfunc(data):
  return HashOut()

# Utility functions
def verify_sig(private_key, hex_msg, r, s):
  print("r", hex(r), "s", hex(s))
  print("r < order", r < order, "; s < order", s < order, "; r < p", r < p)
  print("order", "0x060c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1")
  print("rrrrr", hex(r))
  r %= order
  assert(r < order)
  assert(s < order)
  assert(int(private_key.to_string().hex(), 16) < order)
  assert(int(hex_msg, 16) < order)

  message = bytes.fromhex(hex_msg)
  signature = sigencode_string(r, s, order)
  verifying_key = private_key.get_verifying_key()

  return verifying_key.verify(signature, message, hashfunc=hashfunc)

def der_decode(signature):
     # Extract R and S lengths
    r_length = int(signature[6:8], 16) * 2  # Multiply by 2 to get length in hex characters
    s_length = int(signature[10 + r_length:12 + r_length], 16) * 2

    # Extract R and S values
    r_value = signature[8:8 + r_length]
    s_value = signature[12 + r_length:12 + r_length + s_length]

    # Calculate bit lengths
    r_bit_length = len(bin(int(r_value, 16))[2:])
    s_bit_length = len(bin(int(s_value, 16))[2:])

    return (r_value, s_value), (r_bit_length, s_bit_length)

# Define the custom short Weierstrass curve parameters
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
a =     0x10216f7ba065e00de81ac1e7808072c9b8114d6d7de87adb16a0a72f1a91f6a0
b =     0x23d885f647fed5743cad3d1ee4aba9c043b4ac0fc2766658a410efdeb21f706e
Gx =    0x1fde0a3cac7cb46b36c79f4c0a7a732e38c2c7ee9ac41f44392a07b748a0869f
Gy =    0x203a710160811d5c07ebaeb8fe1d9ce201c66b970d66f18d0d2b264c195309aa
order = 0x060c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1

# Check p is same as bn254 scalar field
# https://github.com/ethereum/EIPs/blob/master/EIPS/eip-197.md#definition-of-the-groups
print("Curve validation")
print("Valid p?", p == 21888242871839275222246405745257275088548364400416034343698204186575808495617)
print()

# Create the curve and generator point
curveFp = ellipticcurve.CurveFp(p, a, b)
generator = ellipticcurve.Point(curveFp, Gx, Gy, order=order)
curve = curves.Curve('babyjubjub', curveFp, generator, None)

# test verify_sig function with old sigs
print("Test 3 old signatures with random secret key and abadbabe message")
old_sk_val = [
  0x04031627028b95196e3bfe3b73c894d814dadedb20c6d7ed83e274c95e00bfc3
]
old_sk_real = [SigningKey.from_secret_exponent(sk, curve=curve) for sk in old_sk_val]
old_hashes = [
  "abadbabeabadbabeabadbabeabadbabe"
]
old_sigs = [
  "3044022002A043A728D9C86A5C82D0AA7455FC148EE2C91993325CBB307EB94D8434C39F022002470171EEC9726D71F9CD194D876FC8762CA2BE1FF7B30ACD5DAF9762BE2438",
  "304402200579E805639DB82135A1A773B4C4A8861F236F1E343271DA0E1417AAF6345EDC0220026C3BC30E69019DD8C724680C812E9AC82214403198531B6B9556C745261268",
  "304402200041DCA2A8BF30D1B630A71702419F7BAFDCC8E1E417E8AD94379D74C0D161FD022002FCAA7A8E69C21AA800A8FC259891CF98314FB68E5DC6A844FF5A568CCD779F"
]
for sig in old_sigs:
  (r, s), (r_bit_length, s_bit_length) = der_decode(sig)
  print(verify_sig(old_sk_real[0], old_hashes[0], int(r, 16), int(s, 16)))
print("Initial verification complete\n")

# test new 
print("Test new signatures with different secret keys and differet messages")
sk_val = [
  0x021756C0B29244D8B03E5DFF686D4442FFF80890428213093C16099CC7B098C3,
  0x05291BA280B7668745E3614C91A523F8CE5639BDAB248013E2913BF87EB1982A,
  0x0219F247D81378B0DE3903ADC3AB066FC84CE460B8F03B173DC96B43FC9C5B5E,
  0x0192149EB4E444C8128F20C61788F8398506C9FF9376DBF575AF875060518BEA,
  0x025867742C90CB8926BB5CE3CD298711CFBAC05886085DABA6ACD314130B91D7
]
sk_real = [SigningKey.from_secret_exponent(sk, curve=curve) for sk in sk_val]
print(hex(sk_val[0]))
hashes = [
  "abadbabeabadbabeabadbabeabadbabe"
]
der_encoded_sigs = [
  "304402200FD2F65517A70A4B477C6AFBF60C110D2662E8449BB4CE3767E79B2F20676B07022001C1D06BB8F8D04F17A61D7BEE2A0F866CB97223DCFA7896C529D387B802826A",
  "3044022023EF30454236A2696D3F537E0BC04455363DF0590D377EE3E28BB6EDF4975BF0022005756396F2E33FD0B36CEF89F3B1E8E825010C1867322432733A29D1384EBB14",
  "304402202558E77A266381F6884821DC70F0B72EDC82C40AD71D99E5C435E225C1FD2759022001399F464B502A093D0D4F7CC9E04142FA81EDA17DE180E9652DF667C9AFC74E",
  "3044022024841FFE81E9BE411E62D7BB7D9DABDD51D2A5F034125DA83AAC009864F8964E0220028A3720555FDC4FF0A25107B947997BCEB420668D3B89A6CCCFFC97984573E8",
  "304402200644961C9B91B24FA993CCD0E1E6BF7D36A967AB5A753002ACDDF5645E9C24C3022002929888B4D6241C2D890EBBAEAE610B78441D952CAA535D7BC40D2A8139903C"
]
for i in range(len(sk_val)):
  sig = der_encoded_sigs[i]
  (r, s), (r_bit_length, s_bit_length) = der_decode(sig)
  try:
    print(verify_sig(sk_real[i], hashes[0], int(r, 16), int(s, 16)))
  except Exception as e:
    print(f"An error occurred: {e}")
