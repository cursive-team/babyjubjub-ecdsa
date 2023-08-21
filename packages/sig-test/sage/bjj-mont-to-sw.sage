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

# Define a secret key and message
sk = Integer("0x04031627028b95196e3bfe3b73c894d814dadedb20c6d7ed83e274c95e00bfc3")
msg = Integer("0x00000000000000000000000000000000abadbabeabadbabeabadbabeabadbabe")
assert(sk < base_order)

def gen_sig(private_key):
    k = randint(1, base_order)
    assert(k < base_order)

    R = k * base
    r = Integer(R.xy()[0]) % base_order
    s = (inverse_mod(k, base_order) * (msg + r * private_key)) % base_order
    return r, s

def verify_sig(private_key, r, s):
    pk = private_key * base

    assert(r < base_order)
    assert(s < base_order)

    # if r >= base_order:
    #     print("r is too large by a factor of", float(r)/base_order)
    # if s >= base_order:
    #     print("s is too large by a factor of", float(s)/base_order)
      
    w = inverse_mod(s, base_order)
    assert((w * s) % base_order == 1)

    u1 = (msg * w) % base_order
    u2 = (r * w) % base_order
    point = u1 * base + u2 * pk

    c = Integer(point.xy()[0]) % base_order

    return hex(c) == hex(r)

print("SAGE signature verification")
for i in range(10):
  r, s = gen_sig(sk)
  print(r, s, verify_sig(sk, r, s))
print()

# Manually verify signatures
print("Card message with padding signature verification")
card_first_sigs = [
  (0x02A043A728D9C86A5C82D0AA7455FC148EE2C91993325CBB307EB94D8434C39F, 0x02470171EEC9726D71F9CD194D876FC8762CA2BE1FF7B30ACD5DAF9762BE2438),
  (0x0579E805639DB82135A1A773B4C4A8861F236F1E343271DA0E1417AAF6345EDC, 0x026C3BC30E69019DD8C724680C812E9AC82214403198531B6B9556C745261268),
  (0x0041DCA2A8BF30D1B630A71702419F7BAFDCC8E1E417E8AD94379D74C0D161FD, 0x02FCAA7A8E69C21AA800A8FC259891CF98314FB68E5DC6A844FF5A568CCD779F)
]
for hex_r, hex_s in card_first_sigs:
  print(hex_r, hex_s, verify_sig(sk, hex_r, hex_s))
print()