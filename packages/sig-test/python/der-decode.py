# Given DER-encoded ECDSA signatures
signatures = [
    "30440220028C30CB4DAF3E58E40057B2BAE230CB7781181A704FAA54E349F4ADC4486273022005621725218ED8BE5AF3F0D22B202435E8917DE1871245526015C83FED71834F0"
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