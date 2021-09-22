pub enum KeyOptions<'a> {
    Seed(&'a str),
    Random,
}

#[derive(Debug, Clone)]
pub enum Network {
    Mainnet,
    Testnet,
}
