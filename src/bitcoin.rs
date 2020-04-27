use crate::secp256k1;
use crate::secp256k1::ToMessage;
use anyhow::{bail, Context};
pub use bitcoin::hash_types::SigHash;
use bitcoin::hashes::Hash;
use bitcoin::util::bip143::SighashComponents;
pub use bitcoin::Transaction;
pub use bitcoin::TxIn;
pub use bitcoin::{Address, OutPoint, SigHashType, TxOut};
use fehler::throws;
use std::{collections::HashMap, str::FromStr};

pub const MAX_SATISFACTION_WEIGHT: u64 = 222;
const MINISCRIPT_TEMPLATE: &str = "and_v(vc:pk(X_from),c:pk(X_to))";

#[derive(Debug)]
pub struct Transactions {
    pub fund: Transaction,
    pub redeem: Transaction,
    pub redeem_tx_digest: SigHash,
    pub refund: Transaction,
    pub refund_tx_digest: SigHash,
}

pub fn make_transactions(
    partial_fund_transaction: Transaction,
    fund_amount: u64,
    spend_amount: u64,
    X_fund_from: &secp256k1::PublicKey,
    X_fund_to: &secp256k1::PublicKey,
    refund_locktime: u32,
    X_redeem: &bitcoin::Address,
    X_refund: &bitcoin::Address,
) -> Transactions {
    let descriptor = descriptor(&X_fund_from, &X_fund_to);

    let fund_output = bitcoin::TxOut {
        value: fund_amount,
        script_pubkey: descriptor.script_pubkey(),
    };

    let Transaction {
        input,
        output: existing_outputs,
        lock_time,
        version,
    } = partial_fund_transaction;

    let joint_output_index = 0;

    let mut outputs = Vec::with_capacity(existing_outputs.len() + 1);

    outputs.insert(joint_output_index, fund_output);
    outputs.extend(existing_outputs);

    let fund_transaction = bitcoin::Transaction {
        input,
        lock_time,
        version,
        output: outputs,
    };

    let input = TxIn {
        previous_output: bitcoin::OutPoint {
            txid: fund_transaction.txid(),
            vout: joint_output_index as u32,
        },
        script_sig: descriptor.unsigned_script_sig(),
        sequence: 0xFFFF_FFFF,
        witness: Vec::new(),
    };

    let (redeem_transaction, redeem_tx_digest) = {
        let output = make_spend_output(spend_amount, &X_redeem);

        let transaction = bitcoin::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input.clone()],
            output: vec![output.clone()],
        };

        let digest = SighashComponents::new(&transaction).sighash_all(
            &input,
            &descriptor.witness_script(),
            fund_amount,
        );

        (transaction, digest)
    };

    let (refund_transaction, refund_tx_digest) = {
        let output = make_spend_output(spend_amount, &X_refund);

        let transaction = bitcoin::Transaction {
            version: 2,
            lock_time: refund_locktime,
            input: vec![input.clone()],
            output: vec![output.clone()],
        };

        let digest = SighashComponents::new(&transaction).sighash_all(
            &input,
            &descriptor.witness_script(),
            fund_amount,
        );

        (transaction, digest)
    };

    Transactions {
        fund: fund_transaction,
        redeem: redeem_transaction,
        redeem_tx_digest: dbg!(redeem_tx_digest),
        refund: refund_transaction,
        refund_tx_digest: dbg!(refund_tx_digest),
    }
}

#[throws(anyhow::Error)]
pub fn complete_spend_transaction(
    mut transaction: Transaction,
    (X_from, mut sig_from): (secp256k1::PublicKey, secp256k1::Signature),
    (X_to, mut sig_to): (secp256k1::PublicKey, secp256k1::Signature),
) -> Transaction {
    sig_from.normalize_s();
    sig_to.normalize_s();

    let satisfier = {
        let mut satisfier = HashMap::with_capacity(2);

        let X_from = ::bitcoin::PublicKey::from_slice(&X_from.serialize_compressed())?;
        let sig_from = ::bitcoin::secp256k1::Signature::from_compact(&sig_from.serialize())?;

        let X_to = ::bitcoin::PublicKey::from_slice(&X_to.serialize_compressed())?;
        let sig_to = ::bitcoin::secp256k1::Signature::from_compact(&sig_to.serialize())?;

        satisfier.insert(X_from, (sig_from, ::bitcoin::SigHashType::All));
        satisfier.insert(X_to, (sig_to, ::bitcoin::SigHashType::All));

        satisfier
    };

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
    digest: SigHash,
    X_from: &secp256k1::PublicKey,
) -> anyhow::Result<secp256k1::Signature> {
    let input = match spend_transaction.input.as_slice() {
        [input] => input,
        [] => bail!(NoInputs),
        [inputs @ ..] => bail!(TooManyInputs(inputs.len())),
    };

    let sig_from = match input
        .witness
        .iter()
        .map(|vec| vec.as_slice())
        .collect::<Vec<_>>()
        .as_slice()
    {
        [_sig_to @ [..], sig_from @ [..], _script @ [..]] => {
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

pub fn tumbler_redeem_amount(tumble_amount: u64, tumbler_fee: u64, redeem_fee_per_wu: u64) -> u64 {
    tumble_amount + tumbler_fee + MAX_SATISFACTION_WEIGHT * redeem_fee_per_wu
}

pub fn receiver_redeem_amount(tumble_amount: u64, redeem_fee_per_wu: u64) -> u64 {
    tumble_amount + MAX_SATISFACTION_WEIGHT * redeem_fee_per_wu
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

    println!("{}", miniscript);

    miniscript::Descriptor::Wsh(miniscript)
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
    use rand::thread_rng;

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

    #[test]
    fn max_satisfaction_weight() {
        let descriptor = descriptor(
            &secp256k1::PublicKey::from_secret_key(
                &secp256k1::SecretKey::random(&mut thread_rng()),
            ),
            &secp256k1::PublicKey::from_secret_key(
                &secp256k1::SecretKey::random(&mut thread_rng()),
            ),
        );

        let max_weight = descriptor.max_satisfaction_weight() as u64;

        assert_eq!(max_weight, MAX_SATISFACTION_WEIGHT)
    }
}
