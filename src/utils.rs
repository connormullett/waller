use hmac_sha512::HMAC;
use rand::prelude::*;
use ripemd160::Ripemd160;
use sha2::{Digest, Sha256, Sha512};

#[inline]
#[doc(hidden)]
pub fn get_random_bytes(num_bytes: usize) -> Vec<u8> {
    let rng = thread_rng();
    let mut rng = rand::rngs::StdRng::from_rng(rng).unwrap();
    let mut buf = vec![0; num_bytes];
    rng.fill(buf.as_mut_slice());
    buf
}

#[inline]
#[doc(hidden)]
pub fn reverse_byte_order(s: String) -> String {
    let string_to_bytes = hex::decode(s).unwrap();
    let mut bytes_reversed = Vec::new();

    for i in string_to_bytes.iter().rev() {
        bytes_reversed.push(*i);
    }

    hex::encode(bytes_reversed)
}

#[inline]
#[doc(hidden)]
pub fn sha256_hash_twice(input: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&input);
    let hash = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(hash);
    let hash = hasher.finalize();
    hash.to_vec()
}

#[inline]
#[doc(hidden)]
pub fn sha256_hash(input: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let hash = hasher.finalize();
    hash.to_vec()
}

#[inline]
#[doc(hidden)]
pub fn sha512_hash(input: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(input);
    let hash = hasher.finalize();
    hash.to_vec()
}

#[inline]
#[doc(hidden)]
pub fn ripemd160_hash(input: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

#[inline]
#[doc(hidden)]
pub fn hmac_sha512_hash(input: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let digest = HMAC::mac(input, key);
    digest.to_vec()
}
