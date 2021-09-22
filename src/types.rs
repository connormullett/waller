pub enum KeyOptions<'a> {
    Seed(&'a str),
    Random,
}

pub enum Network {
    Mainnet,
    Testnet,
}
