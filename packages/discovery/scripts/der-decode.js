function derDecode(signature) {
  // Extract R and S lengths
  r_length = parseInt(signature.slice(6, 8), 16) * 2; // Multiply by 2 to get length in hex characters
  s_length = parseInt(signature.slice(10 + r_length, 12 + r_length), 16) * 2;

  // Extract R and S values
  r = signature.slice(8, 8 + r_length);
  s = signature.slice(12 + r_length, 12 + r_length + s_length);

  return { r, s };
}

module.exports = derDecode;
