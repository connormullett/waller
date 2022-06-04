use std::time::{SystemTime, UNIX_EPOCH};

use crate::reverse_byte_order;

#[derive(Debug, Clone)]
pub enum TransactionVersion {
    One,
}

impl TransactionVersion {
    pub fn as_ver_string(&self) -> String {
        match self {
            TransactionVersion::One => "01000000".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum TransactionType {
    Pay2PubKeyHash,
}

/// A bitcoin Transaction
#[derive(Debug, Clone)]
pub struct Transaction {
    /// The type of the transaction
    tx_type: TransactionType,
    /// transaction version number. currently either 1 or 2
    version: TransactionVersion,
    /// the inputs to the transaction
    tx_in: Vec<TransactionInput>,
    /// vector of transaction outputs
    tx_out: Vec<TransactionOutput>,
    /// a timestamp or block number
    lock_time: u128,
}

impl Transaction {
    pub fn new(
        tx_type: TransactionType,
        inputs: Vec<TransactionInput>,
        outputs: Vec<TransactionOutput>,
        lock_time: Option<u128>,
    ) -> Self {
        match lock_time {
            Some(time) => Self {
                tx_type,
                version: TransactionVersion::One,
                tx_in: inputs,
                tx_out: outputs,
                lock_time: time,
            },
            None => {
                let start = SystemTime::now();
                Self {
                    tx_type,
                    version: TransactionVersion::One,
                    tx_in: inputs,
                    tx_out: outputs,
                    lock_time: start
                        .duration_since(UNIX_EPOCH)
                        .expect("time went backwards")
                        .as_millis(),
                }
            }
        }
    }

    pub fn to_raw(&self) -> String {
        let mut output = String::new();

        // version
        let version = self.version.as_ver_string();
        output.push_str(&version);

        // num inputs
        let num_inputs = self.inputs().len();
        let num_inputs_hex = format!("{:02x}", num_inputs);
        output.push_str(&num_inputs_hex);

        // UTXOs to be spent
        for input in self.inputs().iter() {
            // TXID
            let tx_id = input.previous_output.hash();
            output.push_str(&tx_id);

            // VOUTS
            let vout = input.previous_output.index();
            let vout_hex = reverse_byte_order(format!("{:08x}", vout));
            output.push_str(&vout_hex);

            // num bytes in script sig
            let bytes_hex = format!("{:02x}", input.script_bytes());
            output.push_str(&bytes_hex);

            // script sig
            output.push_str(&hex::encode(input.signature_script.clone()));
        }

        // sequence
        output.push_str("ffffffff");

        // num outputs
        let num_outputs = self.outputs().len();
        let num_outputs_hex = reverse_byte_order(format!("{:02x}", num_outputs));
        output.push_str(&num_outputs_hex);

        // outputs
        for out in self.outputs().iter() {
            // value
            let value = format!("{:016x}", out.value());
            output.push_str(&value);

            // pk script bytes
            let bytes_hex = format!("{:02x}", out.script_bytes());
            output.push_str(&bytes_hex);

            // pk script
            output.push_str(&hex::encode(out.pk_script.clone()));
        }

        // locktime
        let lock_time = format!("{:08x}", self.lock_time);
        output.push_str(&lock_time);

        output
    }

    pub fn get_input(&self, index: usize) -> Option<&TransactionInput> {
        self.tx_in.get(index)
    }

    pub fn get_output(&self, index: usize) -> Option<&TransactionOutput> {
        self.tx_out.get(index)
    }

    pub fn tx_id(&self) -> String {
        // hash all tx data with sha256 twice
        todo!()
    }

    pub fn tx_type(&self) -> TransactionType {
        self.tx_type.clone()
    }

    pub fn version(&self) -> TransactionVersion {
        self.version.clone()
    }

    pub fn inputs(&self) -> Vec<TransactionInput> {
        self.tx_in.clone()
    }

    pub fn outputs(&self) -> Vec<TransactionOutput> {
        self.tx_out.clone()
    }

    /// The amount of inputs in the transaction
    pub fn tx_in_count(&self) -> usize {
        self.tx_in.len()
    }

    /// The amount of outputs in the transaction
    pub fn tx_out_count(&self) -> usize {
        self.tx_out.len()
    }

    pub fn lock_time(&self) -> u128 {
        self.lock_time
    }
}

#[derive(Debug, Clone)]
pub struct TransactionInput {
    /// previous output being spent
    previous_output: OutPoint,
    /// The script to unlock the previous output to be used
    /// as an input in this transaction
    /// to solve this script, the owner of the pub key
    /// needs to provide the original pub key + a valid
    /// signature for it
    /// this looks like <sig><pubkey> + pubkey script + OP_CHECKSIG
    signature_script: Vec<u8>,
}

impl TransactionInput {
    pub fn new(output: OutPoint, signature_script: Vec<u8>) -> Self {
        Self {
            previous_output: output,
            signature_script,
        }
    }

    pub fn script_bytes(&self) -> usize {
        self.signature_script.len()
    }

    pub fn previous_output(&self) -> &OutPoint {
        &self.previous_output
    }
}

/// a tx can have multiple outputs so the Outpoint
/// includes a txid and an output index to refer
/// to a specific output
#[derive(Debug, Clone)]
pub struct OutPoint {
    /// the TXID of the tx holding the output to spend
    hash: String,
    /// output index number of the specific output
    /// to spend from the transaction
    /// the first output is 0x00000000
    /// also referred to as VOUT
    index: i32,
}

impl OutPoint {
    pub fn new(tx_id: String, index: i32) -> Self {
        Self { hash: tx_id, index }
    }

    pub fn hash(&self) -> String {
        self.hash.clone()
    }

    pub fn index(&self) -> i32 {
        self.index
    }
}

/// each output spends a certain number of sats
/// placing them under control of anyone who can
/// satisfy the provided pubkey script
#[derive(Debug, Clone)]
pub struct TransactionOutput {
    /// number of satoshis to spend
    value: i64,
    /// defines the conditions which must be satisfied to spend this output
    pk_script: Vec<u8>,
}

impl TransactionOutput {
    pub fn pubkey_script() {
        // OP_DUP OP_HASH160 <pubkey hash> OP_EQUALVERIFY OP_CHECKSIG
        todo!()
    }

    pub fn value(&self) -> i64 {
        self.value
    }

    pub fn script_bytes(&self) -> usize {
        self.pk_script.len()
    }
}

#[cfg(test)]
mod test {
    use crate::{OutPoint, Transaction, TransactionInput, TransactionOutput, TransactionType};

    #[test]
    pub fn construct_transaction_and_get_raw_data() {
        let utxo = OutPoint::new(
            "7967a5185e907a25225574544c31f7b059c1a191d65b53dcc1554d339c4f9efc".to_string(),
            1,
        );
        let signature_script = hex::decode("47304402206a2eb16b7b92051d0fa38c133e67684ed064effada1d7f925c842da401d4f22702201f196b10e6e4b4a9fff948e5c5d71ec5da53e90529c8dbd122bff2b1d21dc8a90121039b7bcd0824b9a9164f7ba098408e63e5b7e3cf90835cceb19868f54f8961a825").unwrap();
        let input = TransactionInput::new(utxo, signature_script);
        let output = TransactionOutput {
            value: 5453613957652676608,
            pk_script: hex::decode("76a914db4d1141d0048b1ed15839d0b7a4c488cd368b0e88ac").unwrap(),
        };

        let transaction = Transaction::new(
            TransactionType::Pay2PubKeyHash,
            vec![input],
            vec![output],
            Some(00000000),
        );

        let expected = "01000000017967a5185e907a25225574544c31f7b059c1a191d65b53dcc1554d339c4f9efc010000006a47304402206a2eb16b7b92051d0fa38c133e67684ed064effada1d7f925c842da401d4f22702201f196b10e6e4b4a9fff948e5c5d71ec5da53e90529c8dbd122bff2b1d21dc8a90121039b7bcd0824b9a9164f7ba098408e63e5b7e3cf90835cceb19868f54f8961a825ffffffff014baf2100000000001976a914db4d1141d0048b1ed15839d0b7a4c488cd368b0e88ac00000000".to_string();
        assert_eq!(expected, transaction.to_raw());
    }
}
