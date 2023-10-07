use k256::{PublicKey, SecretKey, CompressedPoint, NonZeroScalar};
use crypto_bigint::U256;
use sha2::{Sha512};
use hmac::{Hmac, Mac};
use crypto_bigint::Encoding;

type HmacSha512 = Hmac<Sha512>;

pub struct Node {
  pub prv_key: SecretKey,
  pub pub_key: PublicKey,
  pub chain_code: U256
}

impl Node {

  pub fn derive_child(&self, idx: u32, get_hardend: bool) -> Self {
    let mut idx_num = idx;
    let mut msg: [u8; 37] = [0; 37];

    if get_hardend {
      let prv_bytes = self.prv_key.to_bytes();
      idx_num += 2147483648;
      let idx_bytes = idx_num.to_be_bytes();

      msg[1..33].clone_from_slice(&prv_bytes);
      msg[33..].clone_from_slice(&idx_bytes)
    } else {
      let compressed: CompressedPoint = self.pub_key.into();
      let pub_bytes: [u8; 33] = compressed.into();
      let idx_bytes = idx_num.to_be_bytes();

      msg[..33].clone_from_slice(&pub_bytes);
      msg[33..].clone_from_slice(&idx_bytes);
    }

    let chain_code_bytes: [u8; 32] = self.chain_code.to_be_bytes();
    let mut mac = HmacSha512::new_from_slice(&chain_code_bytes)
        .expect("Hmac can take keys of any size");
    mac.update(&msg);
    let res = mac.finalize().into_bytes();

    let lhs: [u8; 32] = res[0..32].try_into().expect("Secret key is lhs 32 bytes (128 bit)");
    let rhs: [u8; 32] = res[32..64].try_into().expect("Chain code is rhs 32 bytes (128 bit)");

    let mut new_prv = SecretKey::from_slice(&lhs[..]).expect("Secret key is lhs 32 bytes (128 bit)");
    new_prv = SecretKey::from(
      NonZeroScalar::new((*new_prv.as_scalar_primitive() + self.prv_key.as_scalar_primitive()).into()).unwrap()
    );
    let new_chain = U256::from_be_bytes(rhs);

    return Self {
      prv_key: new_prv.clone(),
      pub_key: new_prv.public_key(),
      chain_code: new_chain
    };
  }
}