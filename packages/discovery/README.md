# Discovery

This package is attempting to generate and verify baby jubjub signatures without ZK from software and hardware implementations of the curve. These implementations are for exploration and reference, and are not built for production.

## Status

We are able to generate baby jubjub ECDSA signatures from **Python**, **SAGE**, **JavaCard**. There is an in-progress implementation of generation in **JS**. We are able to verify baby jubjub ECDSA signatures in **Python**, **SAGE**, and **JS**.

Here are the different pairs of generation/verification implementations, and if they successfully verify or not:

| Generating | Verifying | Status |
| ---------- | --------- | ------ |
| Python     | Python    | ✅     |
| SAGE       | SAGE      | ✅     |
| Python     | SAGE      | ✅     |
| SAGE       | Python    | ✅     |
| JavaCard   | SAGE      | ✅     |
| JavaCard   | Python    | ✅     |
| JavaCard   | JS        | ✅     |
| JS         | JS        | ❌     |
| Python     | JS        | ✅     |
| SAGE       | JS        | ✅     |
| JS         | SAGE      | ❌     |

Excitingly, we have our first verification of JavaCard-generated signatures in SAGE and Python, in the `sage/bjj-mont-to-sw.sage` and `python/sig-verify-test.py` files!

JS verification is now working, with an implementation using the `elliptic` library. JS generation has not yet worked. It is important to get this working as we would also like to produce **synthetic** (aka non-NFC) baby jubjub signatures from websites to expand the number of people who can produce sigs.

After we get the other pairs working, we can have strong confidence that the JavaCard definition is working. An additional test to perform is to verify an (efficient) ECDSA baby jubjub signature from JavaCards in Groth16.
