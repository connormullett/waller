use std::time::{SystemTime, UNIX_EPOCH};

use crate::{reverse_byte_order, ripemd160_hash, sha256_hash, sha256_hash_twice, Key};

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

    /// create a presigned transaction
    pub fn pre_sign(&self) -> String {
        let mut presigned_tx = String::new();

        // version
        let version = self.version.as_ver_string();
        presigned_tx.push_str(&version);

        // num inputs
        let num_inputs = self.inputs().len();
        let num_inputs_hex = format!("{:02x}", num_inputs);
        presigned_tx.push_str(&num_inputs_hex);

        // UTXOs to be spent
        for input in self.inputs().iter() {
            // TXID
            let tx_id = input.previous_output.hash();
            presigned_tx.push_str(&tx_id);

            // VOUTS
            let vout = input.previous_output.index();
            let vout_hex = reverse_byte_order(format!("{:08x}", vout));
            presigned_tx.push_str(&vout_hex);

            // num bytes in script sig
            let bytes_hex = format!("{:02x}", input.utxo_pk_script.len());
            presigned_tx.push_str(&bytes_hex);

            // placeholder script sig
            presigned_tx.push_str(&hex::encode(input.utxo_pk_script.clone()));
        }

        // sequence
        presigned_tx.push_str("ffffffff");

        // num outputs
        let num_outputs = self.outputs().len();
        let num_outputs_hex = reverse_byte_order(format!("{:02x}", num_outputs));
        presigned_tx.push_str(&num_outputs_hex);

        // outputs
        for out in self.outputs().iter() {
            // value
            let value = format!("{:016x}", out.value());
            presigned_tx.push_str(&value);

            // pk script bytes
            let bytes_hex = format!("{:02x}", out.script_bytes());
            presigned_tx.push_str(&bytes_hex);

            // pk script
            presigned_tx.push_str(&hex::encode(out.pk_script.clone()));
        }

        // locktime
        let lock_time = format!("{:08x}", self.lock_time);
        presigned_tx.push_str(&lock_time);

        presigned_tx
    }

    /// sign the transaction using a key
    pub fn sign(&self, key: Key) -> String {
        let mut presigned_tx = self.pre_sign();
        presigned_tx.push_str(&format!("{:08x}", 1));

        // sign transaction
        let hash = sha256_hash_twice(&presigned_tx.as_bytes().to_vec());

        let mut signature = key.sign_data(hash);
        signature.push(0x01);

        let pk = key.new_public_key().unwrap();

        let sig_script = format!(
            "{:02x}{}{:02x}{}",
            signature.len(),
            hex::encode(signature),
            pk.len(),
            hex::encode(pk)
        );

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
            let bytes_hex = format!("{:02x}", sig_script.len());
            output.push_str(&bytes_hex);

            // actual sig script
            output.push_str(&hex::encode(sig_script.clone()));
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
    /// to validate this script, the owner of the pub key
    /// needs to provide the original pub key + a valid
    /// signature for it
    signature_script: Vec<u8>,
    // the pk_script of the utxo to be redeemed
    utxo_pk_script: Vec<u8>,
}

impl TransactionInput {
    pub fn new(utxo: TransactionOutput, tx_id: String, index: i32) -> Self {
        let outpoint = OutPoint { hash: tx_id, index };
        Self {
            previous_output: outpoint,
            // left blank until signed
            signature_script: vec![],
            utxo_pk_script: utxo.pk_script,
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
    pub fn new(tx_type: TransactionType, key: Key, value: i64) -> Self {
        let pk_script = match tx_type {
            TransactionType::Pay2PubKeyHash => {
                let sha_hash = sha256_hash(&key.new_public_key().unwrap());
                let pk_hash = ripemd160_hash(&sha_hash);
                format!("76a914{}88ac", hex::encode(pk_hash))
            }
        };

        Self {
            value,
            pk_script: hex::decode(pk_script).unwrap(),
        }
    }

    pub fn value(&self) -> i64 {
        self.value
    }

    pub fn script_bytes(&self) -> usize {
        self.pk_script.len()
    }
}
