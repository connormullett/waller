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

    assert_eq!(
        String::from("03dafb7df037fd4623009af2d4231fc015f0f194da5b5b197dd1d893bea2bae509"),
        hex::encode(pubkey)
    );
}

#[test]
pub fn test_derive_child_private_key() {
    let mnemonic = String::from(
        "fancy lemon deliver stock castle eye answer palm nerve exchange sibling asset",
    );
    let network = Network::Mainnet;

    let key = Key::new(mnemonic, network, true).unwrap();

    let child_private_key = key
        .derive_child_private_key(1, crate::ChildKeyType::Normal)
        .unwrap();

    assert_eq!(
        "8c5c15f7f71c58f98bd0c64d77d982a210dd62d049806daef8affb06e29d7a32".to_string(),
        child_private_key.hex()
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

    assert_eq!(
        "1YeLh5cLf94yHkF7q9F9zXAhKdtyCFejHD1GKRYnvUpngaFSs1xY8q8ko8cUJ18VQAUC1JWV".to_string(),
        address
    );
}
