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
p = "21888242871839275222246405745257275088548364400416034343698204186575808495617"  # replace with your prime

# Convert to Weierstrass form
a, b = montgomery_to_weierstrass(A, p)

print("a", hex(a))
print("b", hex(b))

# Now you can define your Weierstrass curve
E = EllipticCurve(GF(p), [a, b])

# Validate order of curve
order = E.order()
if order == 21888242871839275222246405745257275088614511777268538073601725287587578984328:
    print("This is the correct order!")
else:
    print("This is the wrong order!")

# Verify if Marcus's generator is valid
P = E(7296080957279758407415468581752425029516121466805344781232734728858602888112, 4258727773875940690362607550498304598101071202821725296872974770776423442226) 
is_generator = (order == P.order())

if is_generator:
    print(P.xy(), "is a generator for curve E")
else:
    print("P is not a generator for E")
    
# Verify signature manually
sk = Integer("0xabadbabeabadbabeabadbabeabadbabe")
msg = Integer("0xabadbabeabadbabeabadbabeabadbabe")
pk = sk * P
r = Integer("0xD47ADE8DCF5E8A8BD7EB3B3A73251489E5C70E45AA5DEFFDB56ACC23E52D5D9C")
s = Integer("0xF401C2C2C1A98952FD14FE53E5B5B6D40BE6796FB772D224FECC56FAAF43C8A1")

if r >= order:
    print("r is too large", (r - order)//order)
if s >= order:
    print("s is too large", (s - order)//order)
    
w = inverse_mod(s, order)
u1 = (msg * w) % order
u2 = (r * w) % order
point = u1 * P + u2 * pk

if point[0] == (r % order):
    print("The signature is valid.")
else:
    print("The signature is invalid.")

"""
a 0x10216f7ba065e00de81ac1e7808072c9b8114d6d7de87adb16a0a72f1a91f6a0
b 0x23d885f647fed5743cad3d1ee4aba9c043b4ac0fc2766658a410efdeb21f706e
This is the correct order!
Order of the curve: 21888242871839275222246405745257275088614511777268538073601725287587578984328
(7296080957279758407415468581752425029516121466805344781232734728858602888112, 4258727773875940690362607550498304598101071202821725296872974770776423442226) is a generator for curve E
"""


