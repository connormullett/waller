#![allow(unused_imports)]
use secp256k1::constants::CURVE_ORDER;

use crate::{generate_mnemonic, Key, Network};

#[test]
pub fn test_new_key() {
    let mnemonic = String::from(
        "fancy lemon deliver stock castle eye answer palm nerve exchange sibling asset",
    );
    let network = Network::Mainnet;

    let key = Key::new(mnemonic, network, false).unwrap();

    let wif = key.to_wif();
    let key_from_wif = Key::from_wif(wif).unwrap();

    assert_eq!(key_from_wif.bytes(), key.bytes())
}

#[test]
pub fn test_generate_mnemonic() {
    let mnemonic = generate_mnemonic();
    assert!(!mnemonic.is_empty());
}

#[test]
pub fn test_public_key() {
    let mnemonic = String::from(
        "fancy lemon deliver stock castle eye answer palm nerve exchange sibling asset",
    );
    let network = Network::Mainnet;

    let key = Key::new(mnemonic, network, true).unwrap();

    let pubkey = key.new_public_key().unwrap();

    println!("len {}", pubkey.len());
    println!("key {}", hex::encode(&pubkey));
    assert_eq!(
        String::from("03dafb7df037fd4623009af2d4231fc015f0f194da5b5b197dd1d893bea2bae509"),
        hex::encode(pubkey)
    );
}

#[test]
pub fn test_address() {
    let mnemonic = String::from(
        "fancy lemon deliver stock castle eye answer palm nerve exchange sibling asset",
    );
    let network = Network::Mainnet;

    let key = Key::new(mnemonic, network, true).unwrap();

    let address = key.address().unwrap();

    println!("address :: {}", address);
}
