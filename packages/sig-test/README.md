# sig-test

This package is attempting to generate and verify baby jubjub signatures without ZK from software and hardware implementations of the curve.

## Status

We are able to generate baby jubjub ECDSA signatures from **Python**, **SAGE**, **JavaCard**. There is an in-progress implementation of generation in **Node.JS**.

We are able to verify baby jubjub ECDSA signatures in **Python**, **SAGE**. There is an in-progress implementation of verification in **Node.JS**.

Here are the different pairs of generation/verification implementations, and if they successfully verify or not:

| Generating | Verifying | Status |
| ---------- | --------- | ------ |
| py         | py        | ✅     |
| SAGE       | SAGE      | ✅     |
| JavaCard   | SAGE      | ✅     |
| JavaCard   | Python    | ❌     |
| Python     | SAGE      | ❌     |
| SAGE       | Python    | ❌     |
| JavaCard   | Node.JS   | ❌     |

Excitingly, we have our first verification of JavaCard-generated signatures in SAGE, in the `sage/bjj-mont-to-sw.sage` file! The Python generation/verification seems to be doing some truncation of the digest message to fit in Fp, and thus isn't interoperable yet. But I am hoping that bug should be easy to fix.

After we get the other pairs working, we can have strong confidence that the JavaCard definition is working. An additional test should be to perform is to verify an (efficient) ECDSA signature from JavaCards in Groth16.
