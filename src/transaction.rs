#[derive(Debug)]
pub struct RawTransaction {}

#[derive(Debug)]
pub struct TransactionInput {
    /// previous output being spent
    previous_output: OutPoint,
    /// number of bytes in sig script. Max is 10_000
    script_bytes: usize,
    /// a script-language script with satisfies the conditions
    /// placed in the outpoints pubkey script
    /// should only contain data pushes
    signature_script: String,
    /// sequence number. Default is 0xffffffff
    sequence: u32,
}

/// a tx can have multiple outputs so the Outpoint
/// includes a txid and an output index to refer
/// to a specific output
#[derive(Debug)]
pub struct OutPoint {
    /// the TXID of the tx holding the output to spend
    hash: String,
    /// output index number of the specific output
    /// to spend from the transaction
    /// the first output is 0x00000000
    index: i32,
}

/// each output spends a certain number of sats
/// placing them under control of anyone who can
/// satisfy the provided pubkey script
#[derive(Debug)]
pub struct TransactionOutput {
    /// number of satoshis to spend
    value: i64,
    /// number of bytes in the pubkey script. max is 10_000 bytes
    pk_script_bytes: usize,
    /// defines the conditions which must be satisfied to spend this output
    pk_script: String,
}
