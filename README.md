# bip-32

## Overview

This repository includes implementations of Heirarchical Deterministic Wallets (as specified in [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)) in both Rust and Python. Python was the initial (and much less organized) version of the project. After I felt like I understood the mechanics behind HD Wallets, I redid it in Rust to learn the language.

Below is information for the Rust implementation. Please refer to [`./bip-32/old_py`](./old_py) for more information on the Python implementation.

## Installation

As this project was intended to be educational, it will not be available as a public crate. If you want to use this locally, please install the raw source code.

You can build the source by running `$ cargo build` and run `cargo test` the test vectors found in BIP-32.

You can use this crate in another module by adding the following to your `Cargo.toml`:

```toml
...
[dependencies]
zobie_bip32 = {package = "zobie_bip32", path="/path/to/dir"}
...
```

## Usage

### Wallet Creation via Seed

Random seeds can be used to initialize a wallet. This was implemented primarily for the test vectors in BIP-32. These seeds are byte arrays declared as `&[u8]`. See below for an example.

```rust
use zobie_bip32::HDWallet;
use hex_literal::hex;

// Get a seed as byte array
let seed = hex!("000102030405060708090a0b0c0d0e0f");

// Initialize new wallet
let wallet = HDWallet::new_from_seed(&seed);
```

### Wallet Creation via Mnemonic

Mnemonic word lists as specified in [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) can also be used to generate a wallet. [infincia/bip39-rs](https://github.com/infincia/bip39-rs) offers a pure rust implementation of BIP-39, which is used here. See below for an example.

```rust
use zobie_bip32::HDWallet;
use bip39::{Mnemonic, Language};

// Specify mnemonic parameters
let language = Language::English;
let num_words = 12; // can be 12, 15, 18, 21, or 24
let passphrase = "some phrase";

// Generate list of mnemonics given the language
let mnemo = Mnemonic::generate_in(language, num_words)
  .expect("Cryptographically secure mnemonic");
let words = mnemo.to_string();

// Create Wallet
let wallet = HDWallet::new_from_words(language, &words, &passphrase);
```

### HD-Wallet Navigation

using `pub fn get(&self, path: &str) -> String`, you can get an extended format key found at a specified path. Use `M` to get an extended public key, and `m` to get an extendend private key.

Children are specified using their index, for example, `M/0` refers to the extended public key of the 0th child.

Hardened children are identified using an apostrophe, for example, `M/0'` refers to the extended public key of the 0th *hardened* child.

```rust
use zobie_bip32::HDWallet;
use hex_literal::hex;

let seed = hex!("000102030405060708090a0b0c0d0e0f");
let wallet = HDWallet::new_from_seed(&seed);

// 'xpub661M...EGMcet8'
// 'xprv9s21...BxrMPHi'
wallet.get("M");
wallet.get("m");

// 'xpub68Gm...XvgGDnw'
// 'xprv9uHR...d2bhkJ7'
wallet.get("M/0'")
wallet.get("m/0'")

// 'xpub6ASu...ppuCkwQ'
// 'xprv9wTY...A1xe8fs'
wallet.get("M/0'/1")
wallet.get("m/0'/1")
```

#### Example Paths

|     HD Path     | Key described                                                                                                                       |
| :-------------: | :---------------------------------------------------------------------------------------------------------------------------------- |
|     `m/0`     | First child private key from the master key                                                                                         |
|    `m/0/0`    | The first grandchild private key from the first child                                                                               |
|   `m/0'/0`   | The first normal grandchild from the first *hardened* child (`m/0'`)                                                             |
|    `m/1/0`    | The first grandchild private key from the second child (`m/1`)                                                                    |
| `M/23/17/0/0` | The first great-great grandchild public key from the first great-grandchild from the 18th grandchild from the 24th child (`M/23`) |

> As found in Mastering Bitcoin: Programming the Open Blockchain by Andreas M. Antonopoulos, Chapter 5

## Disclaimer

This was made purely for educational purposes. Do not use this in production environments or to manage any monetary assets.
