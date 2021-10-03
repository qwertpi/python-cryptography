# python-cryptography
Implementations of cryptographic algorithms (so far Diffie–Hellman–Merkle key exchange, and RSA (key gen, and encryption and decryption of text)) in Python

Feedback and pull requests are very welcome

## Copyright
Copyright © 2021  Rory Sharp All rights reserved.

You may read, execute, modify, and reuse this code for your own interest but **you [MAY NOT use this for real world cryptography (and/or as part of any larger project with any scope other than purely demonstrating cryptographic algorithms)](https://www.vice.com/en/article/wnx8nq/why-you-dont-roll-your-own-crypto)**
## Prerequisites
* [Python 3.6 or later](https://www.python.org/downloads/)
* Scapy (DHMKE only) `pip3 install scapy`
* gmpy2 (RSA only) `apt-get install libmpc-dev;pip3 install gmpy2`
