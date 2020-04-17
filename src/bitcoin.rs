use crate::{ecdsa::ToMessage, secp256k1};
use bitcoin::hash_types::SigHash;
use bitcoin::hashes::Hash;
use bitcoin::util::bip143::SighashComponents;
use bitcoin::Script;
pub use bitcoin::Transaction;
pub use bitcoin::TxIn;
pub use bitcoin::{OutPoint, TxOut};
use fehler::throws;
use std::{collections::HashMap, str::FromStr};

const DESCRIPTOR_TEMPLATE: &str = "and_v(vc:pk(X_1),c:pk(X_2))";
const JOINT_OUTPUT_INDEX: usize = 0;

pub fn make_fund_transaction(
    partial_transaction: Transaction,
    amount: u64,
    X_1: &secp256k1::PublicKey,
    X_2: &secp256k1::PublicKey,
) -> Transaction {
    let fund_output = make_fund_output(amount, X_1, X_2);

    let Transaction {
        input,
        output: existing_outputs,
        lock_time,
        version,
    } = partial_transaction;

    let mut outputs = Vec::with_capacity(existing_outputs.len() + 1);

    outputs[JOINT_OUTPUT_INDEX] = fund_output;
    outputs.extend(existing_outputs);

    bitcoin::Transaction {
        input,
        lock_time,
        version,
        output: outputs,
    }
}

pub fn make_spend_transaction(
    fund_transaction: &Transaction,
    amount: u64,
    beneficiary: &secp256k1::PublicKey,
    locktime: u32,
) -> (Transaction, SigHash) {
    let joint_output = fund_transaction.output[JOINT_OUTPUT_INDEX].clone();
    let joint_outpoint = bitcoin::OutPoint {
        txid: fund_transaction.txid(),
        vout: JOINT_OUTPUT_INDEX as u32,
    };

    let input = make_redeem_input(joint_outpoint);
    let output = make_spend_output(amount, &beneficiary);

    let transaction = bitcoin::Transaction {
        version: 2,
        lock_time: locktime,
        input: vec![input.clone()],
        output: vec![output],
    };

    let digest = SighashComponents::new(&transaction).sighash_all(
        &input,
        &joint_output.script_pubkey,
        joint_output.value,
    );

    (transaction, digest)
}

#[throws(anyhow::Error)]
pub fn complete_spend_transaction(
    mut transaction: Transaction,
    (X_1, sig_1): (secp256k1::PublicKey, secp256k1::Signature),
    (X_2, sig_2): (secp256k1::PublicKey, secp256k1::Signature),
) -> Transaction {
    let mut satisfier = HashMap::with_capacity(2);
    satisfier.insert(
        ::bitcoin::PublicKey::from_slice(&X_1.serialize_compressed())?,
        (
            ::bitcoin::secp256k1::Signature::from_compact(&sig_1.serialize())?,
            ::bitcoin::SigHashType::All,
        ),
    );
    satisfier.insert(
        ::bitcoin::PublicKey::from_slice(&X_2.serialize_compressed())?,
        (
            ::bitcoin::secp256k1::Signature::from_compact(&sig_2.serialize())?,
            ::bitcoin::SigHashType::All,
        ),
    );

    // TODO: Should be the same instance as the one used for the fund transaction
    let descriptor = descriptor(&X_1, &X_2);
    descriptor.satisfy(&mut transaction.input[0], satisfier)?;

    transaction
}

fn descriptor(
    X_1: &secp256k1::PublicKey,
    X_2: &secp256k1::PublicKey,
) -> miniscript::Descriptor<bitcoin::PublicKey> {
    let X_1 = hex::encode(X_1.serialize_compressed().to_vec());
    let X_2 = hex::encode(X_2.serialize_compressed().to_vec());

    let descriptor = DESCRIPTOR_TEMPLATE
        .replace("X_1", &X_1)
        .replace("X_2", &X_2);
    miniscript::Descriptor::<bitcoin::PublicKey>::from_str(&descriptor).expect("a valid descriptor")
}

fn make_redeem_input(joint_outpoint: OutPoint) -> TxIn {
    TxIn {
        previous_output: joint_outpoint,
        script_sig: Script::new(), // this is empty because it is a witness transaction
        sequence: 0xFFFF_FFFF,     // TODO: What is the ideal sequence for the redeem tx?
        witness: Vec::new(),       // this is empty because we cannot generate the signatures yet
    }
}

fn make_fund_output(
    amount: u64,
    X_1: &secp256k1::PublicKey,
    X_2: &secp256k1::PublicKey,
) -> bitcoin::TxOut {
    let descriptor = descriptor(&X_1, &X_2);

    bitcoin::TxOut {
        value: amount,
        script_pubkey: descriptor.script_pubkey(),
    }
}

fn make_spend_output(amount: u64, beneficiary: &secp256k1::PublicKey) -> TxOut {
    let script_pubkey = make_p2wpkh_script_pubkey(beneficiary, bitcoin::Network::Regtest);

    TxOut {
        value: amount,
        script_pubkey,
    }
}

fn make_p2wpkh_script_pubkey(identity: &secp256k1::PublicKey, network: bitcoin::Network) -> Script {
    bitcoin::Address::p2wpkh(
        &bitcoin::PublicKey {
            compressed: true,
            key: bitcoin::secp256k1::PublicKey::from_slice(&identity.serialize_compressed())
                .unwrap(),
        },
        network,
    )
    .script_pubkey()
}

impl ToMessage for SigHash {
    fn to_message(&self) -> [u8; 32] {
        self.into_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_policy() {
        // Describes the spending policy of the fund transaction in the A2L protocol.
        //
        // Our spending policy requires that both parties sign the transaction, i.e. a 2 out of 2 multi-signature.
        let spending_policy = "and(pk(X_1),pk(X_2))";
        let miniscript = miniscript::policy::Concrete::<String>::from_str(spending_policy)
            .unwrap()
            .compile()
            .unwrap();

        let descriptor = format!("{}", miniscript);

        println!("{}", descriptor);
    }
}
