#![allow(unused_imports)]
use secp256k1::constants::CURVE_ORDER;

use crate::{generate_mnemonic, ChildKeyType, Key, Network};

#[test]
pub fn test_new_key() {
    let mnemonic = String::from(
        "fancy lemon deliver stock castle eye answer palm nerve exchange sibling asset",
    );
    let network = Network::Mainnet;

    let key = Key::new(mnemonic, network, true).unwrap();

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
pub fn test_derive_child_normal_private_key() {
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
pub fn test_derive_child_hardened_private_key() {
    let mnemonic = String::from(
        "fancy lemon deliver stock castle eye answer palm nerve exchange sibling asset",
    );
    let network = Network::Mainnet;

    let key = Key::new(mnemonic, network, true).unwrap();

    let child_private_key = key
        .derive_child_private_key(2147483648, ChildKeyType::Hardened)
        .unwrap();

    assert_eq!(
        "cbecb80118ebcce68e9d38b11b52beb29be4d5beea4a80230e6f7899fff0a715".to_string(),
        child_private_key.hex()
    );
}

#[test]
pub fn test_derive_child_public_key() {
    let mnemonic = String::from(
        "fancy lemon deliver stock castle eye answer palm nerve exchange sibling asset",
    );
    let network = Network::Mainnet;

    let key = Key::new(mnemonic, network, true).unwrap();

    let pubkey = key.derive_child_public_key(1).unwrap();

    assert_eq!("028be92ede5feab623905b30d1b1d87d477c1524ddb6f8f98ca122fbcf7e59870c5a7832455a67d351cf99fd030bb1d9a558f6a0cadb9bf9144c7010636f4224c4", hex::encode(pubkey));
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
