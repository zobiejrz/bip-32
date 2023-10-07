# bip-32

## Overview

This directory contains a pure Python implementation of Heirarchical Deterministic Wallets (as specified in [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)). This was the starting point for learning how HD Wallets work, and as such it is *not* pretty code. Apologies in advance.

## Usage

`Constants.py`, `AddressGenerator.py` and `Wallet.py` all include various functions, variables, and objects used to generate public/private key combinations and to generate HD Wallets.

`bitcoin_address.ipynb` and `wallet.ipynb` are the jupyter notebooks where I experimented with generating public/private keys and with generating HD Wallets, respectively.

Putting all five files into the same directory and using the two notebooks is the best way to both avoid looking at the spaghetti code I made, but still see the pretty notebooks make use of them.

One of the many advantages the Rust implementation has over the python is that I implement the elliptic curve math myself for the most part in Python. This is a part of what contributed to how bulky and messy it is, so apologies again if you end up deciding to brave those files.

## Disclaimer

This was made purely for educational purposes. Do not use this in production environments or to manage any monetary assets.
