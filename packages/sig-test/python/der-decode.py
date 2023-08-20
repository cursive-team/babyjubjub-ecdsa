# Given DER-encoded ECDSA signatures
signatures = [
    "3044022017B55369D9D4ABCA7E486B9DD826258E89F4877338960401392319C74F9C2477022016EC6E521E0719DC29F4FD08BC0AA5AE81FDC777725A977A4B18FDC79C76D2EE",
    "304402201C8FB9A627A61B36E41C296F4FD8AAC85FF1C054C2A0924255E5B6D04F88A43D0220031F7A9782ACFD3F6F5C09FA8B2BDA093C2261C7FA9B1583F976016BF585856C",
    "30440220092298443A4112DD00581CDB1BCD959F05BB3DB8103121AA06E799492790364A02203F91308283DF79EC4A543F0F3C32D7C197238BCE1EAD127E1AB24DC42E6B3DD9"
]

# Extract R and S values and their bit lengths
values, lengths = [], []
for signature in signatures:
    # Extract R and S lengths
    r_length = int(signature[6:8], 16) * 2  # Multiply by 2 to get length in hex characters
    s_length = int(signature[10 + r_length:12 + r_length], 16) * 2

    # Extract R and S values
    r_value = signature[8:8 + r_length]
    s_value = signature[12 + r_length:12 + r_length + s_length]

    # Calculate bit lengths
    r_bit_length = len(bin(int(r_value, 16))[2:])
    s_bit_length = len(bin(int(s_value, 16))[2:])

    # split this into 2 arrays with values and lengths
    values.append((r_value, s_value))
    lengths.append((r_bit_length, s_bit_length))

for v in values:
    print(v)
for l in lengths:
    print(l)