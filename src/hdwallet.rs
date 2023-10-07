use k256::{PublicKey, SecretKey, CompressedPoint};
use crypto_bigint::U256;
use sha2::{Sha512, Sha256, Digest};
use ripemd::{Ripemd160};
use hmac::{Hmac, Mac};
use crypto_bigint::Encoding;
use bip39::{Mnemonic, Language};
use hex_literal::hex;

type HmacSha512 = Hmac<Sha512>;

#[allow(dead_code)]
pub struct HDWallet{
  master_prv_key: SecretKey,
  master_pub_key: PublicKey,
  master_chain_code: U256
}

#[allow(dead_code)]
impl HDWallet {
    pub fn new_from_seed(seed: &[u8]) -> Self {
        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")
          .expect("Hmac can take keys of any size");
        mac.update(&seed);
        let res = mac.finalize().into_bytes();

        let gen_prv: SecretKey = SecretKey::from_slice(&res[0 .. 32]).expect("Secret key is lhs 32 bytes (128 bit)");
        let gen_pub: PublicKey = gen_prv.public_key();
        let gen_chain_code_bytes: [u8; 32] = res[32 .. 64].try_into().expect("Chain code is rhs 32 bytes (128 bit)");
        let gen_chain_code: U256 = U256::from_be_bytes(gen_chain_code_bytes);

        return Self {
          master_prv_key: gen_prv,
          master_pub_key: gen_pub,
          master_chain_code: gen_chain_code,
        };
    }

    pub fn new_from_words(language: Language, words: &str, passphrase: &str) -> Self {
        let m = Mnemonic::parse_in_normalized(language, &words).expect("Generated Mnemonic");
        let seed = m.to_seed(passphrase);

        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")
          .expect("Hmac can take keys of any size");
        mac.update(&seed);
        let res = mac.finalize().into_bytes();

        let gen_prv: SecretKey = SecretKey::from_slice(&res[0 .. 32]).expect("Secret key is lhs 32 bytes (128 bit)");
        let gen_pub: PublicKey = gen_prv.public_key();
        let gen_chain_code_bytes: [u8; 32] = res[32 .. 64].try_into().expect("Chain code is rhs 32 bytes (128 bit)");
        let gen_chain_code: U256 = U256::from_be_bytes(gen_chain_code_bytes);

        return Self {
          master_prv_key: gen_prv,
          master_pub_key: gen_pub,
          master_chain_code: gen_chain_code,
        };
    }

    pub fn get(&self, path: &str) -> String {
      let mut operations: Vec<&str> = path.split("/").collect();
      operations.reverse();

      let get_prv_key = operations.pop().unwrap() == "m";

      let mut depth = 0;
      let mut prev_fingerprint: [u8; 4] = [0; 4];
      let mut idx: u32 = 0;
      let mut get_hardened = false;
      let mut node = crate::walletnode::Node {
        prv_key: self.master_prv_key.clone(), 
        pub_key: self.master_pub_key,
        chain_code: self.master_chain_code
      };

      while operations.len() > 0 {
        prev_fingerprint = HDWallet::serialize_fingerprint(node.pub_key);
        depth += 1;
        let mut op = operations.pop().expect("Get the next operation").to_string();
        get_hardened = op.chars().last().unwrap() == '\'';
        if get_hardened {
          op.pop();
        }
        idx = op.parse().unwrap();

        node = node.derive_child(idx, get_hardened);
      }

      let mut val:[u8; 33] = [0; 33];
      if get_prv_key {
        val[1..].clone_from_slice(&node.prv_key.to_bytes());
      } else {
        let compressed: CompressedPoint = node.pub_key.into();
        let bytes: [u8; 33] = compressed.into();
        val[..].clone_from_slice(&bytes);
      }
      return HDWallet::extended_format_key(get_prv_key, depth, prev_fingerprint, get_hardened, idx, node.chain_code.to_be_bytes(), val);
    }

    fn serialize_fingerprint(key: PublicKey) -> [u8; 4] {
      let compressed: CompressedPoint = key.into();
      let bytes: [u8; 33] = compressed.into();

      let mut hasher = Sha256::new();
      hasher.update(bytes);
      let a = hasher.finalize();

      let mut hasher = Ripemd160::new();
      hasher.update(a);
      let out = hasher.finalize();

      let mut result: [u8; 4] = [0; 4];
      result.clone_from_slice(&out[0..4]);
      return result;
    }

    fn extended_format_key(is_private: bool, depth: u8, parent_fingerprint: [u8; 4], is_hardened: bool, idx: u32, chain_code: [u8; 32], key: [u8; 33]) -> String {
      let mut buf: [u8; 78] = [0; 78];
      
      let version = if is_private { hex!("0488ADE4") } else { hex!("0488B21E") };
      buf[0..4].clone_from_slice(&version);

      buf[4] = depth;

      buf[5 .. 9].clone_from_slice(&parent_fingerprint);

      let child_number: [u8; 4];
      if is_hardened {
        child_number = (idx + 2147483648).to_be_bytes();
      } else {
        child_number = idx.to_be_bytes();
      }
      buf[9..13].clone_from_slice(&child_number);
      buf[13..45].clone_from_slice(&chain_code);
      buf[45..78].clone_from_slice(&key);

      return HDWallet::b58checksum(&buf);
    }

    fn b58checksum(buf: &[u8]) -> String {
      let mut hasher = Sha256::new();
      hasher.update(buf);
      let first = hasher.finalize();

      let mut hasher = Sha256::new();
      hasher.update(first);
      let second = hasher.finalize();

      let checksum = &second[0..4];

      let mut data = Vec::new();
      data.extend_from_slice(&buf[..]);
      data.extend_from_slice(&checksum[..]);

      return bs58::encode(data).into_string();
    }
}