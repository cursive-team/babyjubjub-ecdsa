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

if base.order().is_prime() and base.order() == 2736030358979909402780800718157159386076813972158567259200215660948447373041:
    print("Example base point")
    print(base.xy())
    print([hex(int(c)) for c in base.xy()])

# Verify signature manually
sk = Integer("0xabadbabeabadbabeabadbabeabadbabe")
msg = Integer("0xabadbabeabadbabeabadbabeabadbabe")

if sk < base_order:
    print(sk, "is a fine private key")
else:
    print(sk, "is not an okay private key")

# Manually verify signature
pk = sk * base
r = Integer("0x5ab098d6016e6f886d3deca0cb25f311f45129fe6679d19fdc7de80510fb8ea")
s = Integer("0x4c03f936209f7b00f1db3893715665ece1642a90217a60ee903d686ca2b0384")

if r >= base_order:
    print("r is too large")
if s >= base_order:
    print("s is too large")
    
w = inverse_mod(s, base_order)
u1 = (msg * w) % base_order
u2 = (r * w) % base_order
point = u1 * base + u2 * pk

if point[0] == r:
    print("The signature is valid.")
else:
    print("The signature is invalid.")
