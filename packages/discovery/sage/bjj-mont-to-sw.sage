def montgomery_to_weierstrass(A, p):
    # from https://safecurves.cr.yp.to/equation.html
    
    # Define the finite field
    Fp = GF(p)
    
    # Do the calculations in the finite field
    A = Fp(A)
    three = Fp(3)
    two = Fp(2)
    nine = Fp(9)
    twenty_seven = Fp(27)
    
    a = (three - A^2) / three
    b = (two*A^3 - nine*A) / (twenty_seven)
    
    return a, b

  # Define your Montgomery curve parameter and the prime for the finite field
A = "168698"
p = "21888242871839275222246405745257275088548364400416034343698204186575808495617" 

# Convert to Weierstrass form
a, b = montgomery_to_weierstrass(A, p)

print("Curve params")
print("a", hex(a))
print("b", hex(b))
print("p", hex(int(p)))
print()

# Now you can define your Weierstrass curve
E = EllipticCurve(GF(p), [a, b])

# Validate order of curve
curve_order = E.order()
print("Curve order verification")
print("order", hex(curve_order))

if curve_order == 21888242871839275222246405745257275088614511777268538073601725287587578984328:
    print("This is the correct order!")
else:
    print("This is the wrong order!")
print()

# Create a base point
print("Main subgroup order", hex(int(2736030358979909402780800718157159386076813972158567259200215660948447373041)))
P = E(7296080957279758407415468581752425029516121466805344781232734728858602888112, 4258727773875940690362607550498304598101071202821725296872974770776423442226) 
base = 8 * P
base_order = curve_order / 8
print("Number of bytes in subgroup order")
print(len(hex(int(base_order))[2:]) / 2)

if base.order().is_prime() and base.order() == 2736030358979909402780800718157159386076813972158567259200215660948447373041:
    print("Example base point")
    print([hex(int(c)) for c in base.xy()])
    print()

def gen_sig(private_key, message):
    k = randint(1, base_order)
    assert(k < base_order)

    R = k * base
    r = Integer(R.xy()[0]) % base_order
    s = (inverse_mod(k, base_order) * (message + r * private_key)) % base_order
    return r, s

def verify_sig(private_key, message, r, s):
    pk = private_key * base

    assert(r < base_order)
    assert(s < base_order)

    # if r >= base_order:
    #     print("r is too large by a factor of", float(r)/base_order)
    # if s >= base_order:
    #     print("s is too large by a factor of", float(s)/base_order)
      
    w = inverse_mod(s, base_order)
    assert((w * s) % base_order == 1)

    u1 = (message * w) % base_order
    u2 = (r * w) % base_order
    point = u1 * base + u2 * pk

    c = Integer(point.xy()[0]) % base_order

    return hex(c) == hex(r)

# Define a secret key and message
sk = Integer("0x04031627028b95196e3bfe3b73c894d814dadedb20c6d7ed83e274c95e00bfc3")
msg = Integer("0x00000000000000000000000000000000abadbabeabadbabeabadbabeabadbabe")
assert(sk < base_order)

# Test generation and verification
print("SAGE signature verification")
for i in range(10):
  r, s = gen_sig(sk, msg)
  print(r, s, verify_sig(sk, msg, r, s))
print()

# Generate signatures for Python verification
print("Generating signatures for Python")
for i in range(10):
  r, s = gen_sig(sk, msg)
  print("(" + str(hex(r)) + ", " + str(hex(s)) + "),")
print()

# Verify signatures from Python
print("Python signature verification")
python_sigs = [
  (0x28fe624b15ce8f00155bd8b0b718384883ca1c807d0bf9e3a96496727ebf97f, 0x4a422a0e152692b6a954ef31abb062f5c8a4cb9ad0e9fb335d80448c60d201c),
  (0xd5669de08f118f21dd69002859e73aa359a17dfefb0222263a40812ee26861, 0x487914d3f479c026c047e8998a68a130dd06a5d26495f86493822ef7f0fd966),
  (0x415f4651167ff30c3a570f1a957002b9b5115e9ffbbbeda68a22b9fcd789716, 0x45b8bb4024436fb67eeec186f7834e568c949b548b378b254f57e14876ad745),
  (0x57c66c08196b6782e8fc750200dda6bf2ebffd482d1b36c71ccb3be31c35e3, 0xa39b6b698085df0ffae3b78d10d1b327deeb99773b6f13b98e8e6f0c9fbd92),
  (0x5f3cd065dff53788b212512b4d908dcfe8ac135ae785e93fadb268999a8235b, 0x1c2ec88d3600a5123c3a609ad20c234ceaa47801d5b2c1349ac381eee43d6f3),
  (0x1cfe889f1c1a7398b5fe0d0ac8e9cbca460f33b4f3e59b23ff0134d480c86ea, 0x5b9ecced35393b17325fd511bafa6449ecb3b55fa498cfbe91afb84ce5ae81b),
  (0xbb5ba329bb577f40f67a695aa9d268ce116f675c491213870801068f899178, 0xc97e9906de9f6498a30cd508f7900c3058ad868d30bf36cf8302932ec65d9b),
  (0x24cf83fce998d7846b87cf559153880792e91d754d7d26f4b1bddfeb01618c1, 0x3ad2405a7218727d962364071a55dc9d66eed3e2df11a4ab54a0f68e46735f3),
  (0x579b72913aa3b764394985daf58f6c4a2e85b53ea4da7e9939635761244f159, 0x4ce0b7368f1481931b63667a652ac7400eac44aeabdfe38e9602da3be794764),
  (0xe5ab177565fd6e3aeab23760078e2647e66cd5eedc8e2886fc9bd38824d8b2, 0x318d460ef4994b74a4df47c928dfdf5bd52d4076cde1459642a2905c4ebc95a)
]
for hex_r, hex_s in python_sigs:
  print(hex_r, hex_s, verify_sig(sk, msg, hex_r, hex_s))
print()

# Manually verify card signatures
print("Card message with padding signature verification")
card_first_sigs = [
  (0x02A043A728D9C86A5C82D0AA7455FC148EE2C91993325CBB307EB94D8434C39F, 0x02470171EEC9726D71F9CD194D876FC8762CA2BE1FF7B30ACD5DAF9762BE2438),
  (0x0579E805639DB82135A1A773B4C4A8861F236F1E343271DA0E1417AAF6345EDC, 0x026C3BC30E69019DD8C724680C812E9AC82214403198531B6B9556C745261268),
  (0x0041DCA2A8BF30D1B630A71702419F7BAFDCC8E1E417E8AD94379D74C0D161FD, 0x02FCAA7A8E69C21AA800A8FC259891CF98314FB68E5DC6A844FF5A568CCD779F)
]
for hex_r, hex_s in card_first_sigs:
  print(hex_r, hex_s, verify_sig(sk, msg, hex_r, hex_s))
print()