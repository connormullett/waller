use rand::prelude::*;
use sha2::{Digest, Sha256};

#[inline]
#[doc(hidden)]
pub fn get_random_bytes(num_bits: usize) -> Vec<u8> {
    let rng = thread_rng();
    let mut rng = rand::rngs::StdRng::from_rng(rng).unwrap();
    let mut buf = vec![0; num_bits];
    rng.fill(buf.as_mut_slice());
    buf
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
