use crate::secp256k1;
use crate::secp256k1::ToMessage;
use anyhow::{bail, Context};
use bitcoin::hash_types::SigHash;
use bitcoin::hashes::Hash;
use bitcoin::util::bip143::SighashComponents;
use bitcoin::Script;
pub use bitcoin::Transaction;
pub use bitcoin::TxIn;
pub use bitcoin::{Address, OutPoint, SigHashType, TxOut};
use fehler::throws;
use std::{collections::HashMap, str::FromStr};

const MINISCRIPT_TEMPLATE: &str = "and_v(vc:pk(X_from),c:pk(X_to))";
const JOINT_OUTPUT_INDEX: usize = 0;

pub fn make_fund_transaction(
    partial_transaction: Transaction,
    amount: u64,
    X_from: &secp256k1::PublicKey,
    X_to: &secp256k1::PublicKey,
) -> Transaction {
    let fund_output = make_fund_output(amount, X_from, X_to);

    let Transaction {
        input,
        output: existing_outputs,
        lock_time,
        version,
    } = partial_transaction;

    let mut outputs = Vec::with_capacity(existing_outputs.len() + 1);

    outputs.insert(JOINT_OUTPUT_INDEX, fund_output);
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
    X_to: &bitcoin::Address,
    locktime: u32,
) -> (Transaction, SigHash) {
    let joint_outpoint = bitcoin::OutPoint {
        txid: fund_transaction.txid(),
        vout: JOINT_OUTPUT_INDEX as u32,
    };

    let input = make_redeem_input(joint_outpoint);
    let output = make_spend_output(amount, &X_to);

    let transaction = bitcoin::Transaction {
        version: 2,
        lock_time: locktime,
        input: vec![input.clone()],
        output: vec![output.clone()],
    };

    let digest = SighashComponents::new(&transaction).sighash_all(
        &input,
        &output.script_pubkey,
        output.value,
    );

    (transaction, digest)
}

#[throws(anyhow::Error)]
pub fn complete_spend_transaction(
    mut transaction: Transaction,
    (X_from, sig_from): (secp256k1::PublicKey, secp256k1::Signature),
    (X_to, sig_to): (secp256k1::PublicKey, secp256k1::Signature),
) -> Transaction {
    let mut satisfier = HashMap::with_capacity(2);
    satisfier.insert(
        ::bitcoin::PublicKey::from_slice(&X_from.serialize_compressed())?,
        (
            ::bitcoin::secp256k1::Signature::from_compact(&sig_from.serialize())?,
            ::bitcoin::SigHashType::All,
        ),
    );
    satisfier.insert(
        ::bitcoin::PublicKey::from_slice(&X_to.serialize_compressed())?,
        (
            ::bitcoin::secp256k1::Signature::from_compact(&sig_to.serialize())?,
            ::bitcoin::SigHashType::All,
        ),
    );

    descriptor(&X_from, &X_to).satisfy(&mut transaction.input[0], satisfier)?;

    transaction
}

#[derive(thiserror::Error, Debug)]
#[error("transaction does not spend anything")]
pub struct NoInputs;

#[derive(thiserror::Error, Debug)]
#[error("transaction has {0} inputs, expected 1")]
pub struct TooManyInputs(usize);

#[derive(thiserror::Error, Debug)]
#[error("empty witness stack")]
pub struct EmptyWitnessStack;

#[derive(thiserror::Error, Debug)]
#[error("input has {0} witnesses, expected 3")]
pub struct NotThreeWitnesses(usize);

pub fn extract_signature_by_key(
    spend_transaction: Transaction,
    X_from: &secp256k1::PublicKey,
) -> anyhow::Result<secp256k1::Signature> {
    let input = match spend_transaction.input.as_slice() {
        [input] => input,
        [] => bail!(NoInputs),
        [inputs @ ..] => bail!(TooManyInputs(inputs.len())),
    };

    let joint_output = &spend_transaction.output[JOINT_OUTPUT_INDEX];
    let digest = SighashComponents::new(&spend_transaction).sighash_all(
        &input,
        &joint_output.script_pubkey,
        joint_output.value,
    );

    let sig_from = match input
        .witness
        .iter()
        .map(|vec| vec.as_slice())
        .collect::<Vec<_>>()
        .as_slice()
    {
        [sig_from @ [..], _sig_to @ [..], _script @ [..]] => {
            secp256k1::Signature::parse_der(&sig_from[..sig_from.len() - 1])
                .context("unknown witness layout")?
        }
        [] => bail!(EmptyWitnessStack),
        [witnesses @ ..] => bail!(NotThreeWitnesses(witnesses.len())),
    };

    secp256k1::verify(digest, &sig_from, X_from)
        .context("first signature on witness stack does not verify against the given public key")?;

    Ok(sig_from)
}

fn descriptor(
    X_from: &secp256k1::PublicKey,
    X_to: &secp256k1::PublicKey,
) -> miniscript::Descriptor<bitcoin::PublicKey> {
    let X_from = hex::encode(X_from.serialize_compressed().to_vec());
    let X_to = hex::encode(X_to.serialize_compressed().to_vec());

    let miniscript = MINISCRIPT_TEMPLATE
        .replace("X_from", &X_from)
        .replace("X_to", &X_to);

    let miniscript = miniscript::Miniscript::<bitcoin::PublicKey>::from_str(&miniscript)
        .expect("a valid miniscript");

    miniscript::Descriptor::Wsh(miniscript)
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
    X_from: &secp256k1::PublicKey,
    X_to: &secp256k1::PublicKey,
) -> bitcoin::TxOut {
    let descriptor = descriptor(&X_from, &X_to);

    bitcoin::TxOut {
        value: amount,
        script_pubkey: descriptor.script_pubkey(),
    }
}

fn make_spend_output(amount: u64, X_to: &bitcoin::Address) -> TxOut {
    TxOut {
        value: amount,
        script_pubkey: X_to.script_pubkey(),
    }
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
        let spending_policy = "and(pk(X_from),pk(X_to))";
        let miniscript = miniscript::policy::Concrete::<String>::from_str(spending_policy)
            .unwrap()
            .compile()
            .unwrap();

        let descriptor = format!("{}", miniscript);

        println!("{}", descriptor);
    }
}
