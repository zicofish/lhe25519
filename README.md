## Introduction

Additive homomorphic encryption based on ElGamal Encryption.
- Use well-studied Elliptic Curve Ed25519 (Ed25519 implementation borrowed from Openssl)
- Support up to 40-bit messages
- Use baby-step-giant-step to accelerate decryption


## Test

Please change `MSG_BITS` and `BABY_BITS` in `lhe25519.h` to smaller numbers for a faster test. For example,

`#define MSG_BITS 20`
`#define BABY_BITS 10`

To run our code, please execute the following commands:

`cd build`

`cmake ..`

`make`

`./lhe`

NOTE: You need to first generate the lookup table for the above tests to run successfully. Please check `test.cpp` for details.

## Disclaimer
There is no guarantee that this code is bug-free or has production-level security. Use it at your own risk.

## Contact
zhicong303 AT gmail.com
