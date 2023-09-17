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

def verify_sig(private_key, message, r, s):
    pk = private_key * base

    r %= base_order

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
sk =  Integer("0x021756C0B29244D8B03E5DFF686D4442FFF80890428213093C16099CC7B098C3")
msg = Integer("0x00000000000000000000000000000000abadbabeabadbabeabadbabeabadbabe")
r =   Integer("0xfd2f65517a70a4b477c6afbf60c110d2662e8449bb4ce3767e79b2f20676b07")
s =   Integer("0x1c1d06bb8f8d04f17a61d7bee2a0f866cb97223dcfa7896c529d387b802826a")
verify_sig(sk, msg, r, s)



