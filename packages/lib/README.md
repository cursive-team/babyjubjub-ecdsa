# babyjubjub-ecdsa

This library includes functions for proving and verifying ECDSA signatures over the Baby Jubjub elliptic curve. Some included functionality:

- [x] Javascript verification of Baby Jubjub ECDSA signatures
- [x] Generation and verification of zero knowledge proofs for demonstrating knowledge of a signature from a list of ECDSA public keys
- [x] A definition of the Baby Jubjub curve with conversions between different curve representations
- [x] Various other signature and curve utilities, include public key recovery, DER decoding, and more

### Usage

To see an example of how babyjubjub-ecdsa can be used, see the [demo repo](https://github.com/AndrewCLu/babyjubjub-ecdsa-demo).

### Under the Hood

Much of the code is structured around two different representations of the Baby Jubjub curve: in Short Weierstrass form, and in Twisted Edwards form. We make use of the fact that there exists an isomorphism between these two forms, which can be seen [here](https://www-fourier.univ-grenoble-alpes.fr/mphell/doc-v5/conversion_weierstrass_edwards.html). Plain Javascript signature verification is done in Weierstrass form, and most of the functions that are meant to be interfaced with are based on points in Weierstrass form (public keys, signature r and s values, etc.).

However, for zero knowledge proof generation and verification, we rely upon the Twisted Edwards representation of the curve. Because Twisted Edwards curves have complete addition laws, they are more efficient to work with inside of a circuit. Perhaps most important, the advantage of the [Baby Jubjub curve](https://eips.ethereum.org/EIPS/eip-2494) in particular is that it's base field has the same order as the scalar field of BN254. This allows us to battle-tested tooling straight out of the box, namely circom + SnarkJs with Groth16. Plus, this allows proofs to be easily coverted to smart contract verifiers on Ethereum.

There is one major complication we face, in that ECDSA verification relies upon both base field math (elliptic curve operations) as well as scalar field math (operations with r and s). Especially because we convert points between Short Weierstrass and Twisted Edwards form, this severely complicates how we can generate signatures in one representation and verify it in-circuit in another. A second issue is that all of this wrong-field scalar math dramatically increases the size of our circuit. Incredibly, there is a solution to both of these problems simultaneously: the [Efficient ECDSA formulation](https://personaelabs.org/posts/efficient-ecdsa-1/). Instead of doing traditional ECDSA verification, we generate R, T, U according to Efficient ECDSA, and then transform these points between Weierstrass and Edwards form. The final in-circuit verification check is `s*T + U = pubKey`. We can perform this check using whichever representation we like, as long as T, U, and the public key are correctly converted into that form. For our circuit, we convert everything to Twisted Edwards form and take advantage of slightly more efficient curve operations from circomlib. Lastly, we wrap this ECDSA public key recovery proof with a Merkle proof to prove membership of a signature within a list of public keys. Here we use a circuit setup from [Spartan-ecdsa](https://github.com/personaelabs/spartan-ecdsa/blob/main/packages/circuits/eff_ecdsa_membership/pubkey_membership.circom).
