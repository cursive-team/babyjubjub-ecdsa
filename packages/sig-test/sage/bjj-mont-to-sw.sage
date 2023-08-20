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
    print([hex(int(c)) for c in base.xy()])

# Verify signature manually
sk = Integer("0x24abadbabeabadbabeabadbabeabadbabe")
msg = Integer("0xabadbabeabadbabeabadbabeabadbabe")

if sk < base_order:
    print("Secret key", hex(sk), "is less than main subgroup order")
else:
    print("Secret key", hex(sk), "is greater than main subgroup order")

# Manually verify signatures
pk = sk * base
sigs = [
  ('17B55369D9D4ABCA7E486B9DD826258E89F4877338960401392319C74F9C2477', '16EC6E521E0719DC29F4FD08BC0AA5AE81FDC777725A977A4B18FDC79C76D2EE'),
  ('1C8FB9A627A61B36E41C296F4FD8AAC85FF1C054C2A0924255E5B6D04F88A43D', '031F7A9782ACFD3F6F5C09FA8B2BDA093C2261C7FA9B1583F976016BF585856C'),
  ('092298443A4112DD00581CDB1BCD959F05BB3DB8103121AA06E799492790364A', '3F91308283DF79EC4A543F0F3C32D7C197238BCE1EAD127E1AB24DC42E6B3DD9')
]

for hex_r, hex_s in sigs:
  r = Integer("0x" + hex_r)
  s = Integer("0x" + hex_s)

  print("Signature:", "r", hex_r, "s", hex_s)
  if r >= base_order:
      print("r is too large by a factor of", float(r)/base_order)
  else:
      print("r is fine")
  if s >= base_order:
      print("s is too large by a factor of", float(s)/base_order)
  else:
      print("s is fine")
      
  w = inverse_mod(s, base_order)
  u1 = (msg * w) % base_order
  u2 = (r * w) % base_order
  point = u1 * base + u2 * pk

  if point[0] == (r % base_order):
      print("The signature is valid.")
  else:
      print("The signature is invalid.")

  print()
