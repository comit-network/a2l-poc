use crate::ecdsa;
use crate::secp256k1;
use bitcoin::hashes::Hash;
use bitcoin::util::bip143::SighashComponents;
use bitcoin::Script;
pub use bitcoin::Transaction;
pub use bitcoin::TxIn;
pub use bitcoin::{OutPoint, TxOut};
use std::str::FromStr;

const DESCRIPTOR_TEMPLATE: &str = "and_v(vc:pk(X_1),c:pk(X_2))";

pub fn make_joint_output(
    partial_transaction: Transaction,
    amount: u64,
    X_1: &secp256k1::PublicKey,
    X_2: &secp256k1::PublicKey,
) -> (TxOut, OutPoint) {
    let fund_output = make_fund_output(amount, X_1, X_2);

    let Transaction {
        input,
        output: existing_outputs,
        lock_time,
        version,
    } = partial_transaction;

    let mut outputs = Vec::with_capacity(existing_outputs.len() + 1);
    let joint_output_index = 0;

    outputs[joint_output_index] = fund_output.clone();
    outputs.extend(existing_outputs);

    let fund_transaction = bitcoin::Transaction {
        input,
        lock_time,
        version,
        output: outputs,
    };

    let joint_outpoint = OutPoint {
        txid: fund_transaction.txid(),
        vout: joint_output_index as u32,
    };

    (fund_output, joint_outpoint)
}

pub fn make_unsigned_redeem_transaction(
    joint_outpoint: OutPoint,
    redeem_amount: u64,
    redeem_identity: &secp256k1::PublicKey,
) -> Transaction {
    let input = make_redeem_input(joint_outpoint);
    let output = make_spend_output(redeem_amount, redeem_identity);

    bitcoin::Transaction {
        version: 2,
        lock_time: 0,
        input: vec![input],
        output: vec![output],
    }
}

pub fn make_refund_signature<S: AsRef<secp256k1::SecretKey>>(
    joint_outpoint: OutPoint,
    joint_output: TxOut,
    expiry: u32,
    refund_amount: u64,
    refund_identity: &secp256k1::PublicKey,
    x: &S,
) -> secp256k1::Signature {
    let input = make_refund_input(joint_outpoint);
    let output = make_spend_output(refund_amount, refund_identity);

    let transaction = bitcoin::Transaction {
        version: 2,
        lock_time: expiry,
        input: vec![input.clone()],
        output: vec![output],
    };

    let digest = SighashComponents::new(&transaction).sighash_all(
        &input,
        &joint_output.script_pubkey,
        joint_output.value,
    );
    let refund_digest = secp256k1::Message::parse(&digest.into_inner());

    let (signature, _) = secp256k1::sign(&refund_digest, x.as_ref());

    signature
}

pub fn make_redeem_signature<S: AsRef<secp256k1::SecretKey>, R: rand::Rng>(
    rng: &mut R,
    joint_outpoint: OutPoint,
    joint_output: TxOut,
    redeem_amount: u64,
    redeem_identity: &secp256k1::PublicKey,
    x: &S,
    A: &secp256k1::PublicKey,
) -> ecdsa::EncryptedSignature {
    let input = make_redeem_input(joint_outpoint);
    let output = make_spend_output(redeem_amount, redeem_identity);

    let transaction = bitcoin::Transaction {
        version: 2,
        lock_time: 0,
        input: vec![input.clone()],
        output: vec![output],
    };

    let digest = SighashComponents::new(&transaction).sighash_all(
        &input,
        &joint_output.script_pubkey,
        joint_output.value,
    );

    ecdsa::encsign(rng, x, A, &digest.into_inner())
}

fn make_redeem_input(joint_outpoint: OutPoint) -> TxIn {
    TxIn {
        previous_output: joint_outpoint,
        script_sig: Script::new(), // this is empty because it is a witness transaction
        sequence: 0xFFFF_FFFF,     // TODO: What is the ideal sequence for the redeem tx?
        witness: Vec::new(),       // this is empty because we cannot generate the signatures yet
    }
}

fn make_refund_input(joint_outpoint: OutPoint) -> TxIn {
    TxIn {
        previous_output: joint_outpoint,
        script_sig: Script::new(), // this is empty because it is a witness transaction
        sequence: 0xFFFF_FFFF, // TODO: shouldn't this be 0xFFFF_FFFF - 1 to activate the locktime?
        witness: Vec::new(),   // this is empty because we cannot generate the signatures yet
    }
}

fn make_fund_output(
    amount: u64,
    X_1: &secp256k1::PublicKey,
    X_2: &secp256k1::PublicKey,
) -> bitcoin::TxOut {
    let X_1 = hex::encode(X_1.serialize_compressed().to_vec());
    let X_2 = hex::encode(X_2.serialize_compressed().to_vec());

    let descriptor = DESCRIPTOR_TEMPLATE
        .replace("X_1", &X_1)
        .replace("X_2", &X_2);
    let descriptor = miniscript::Descriptor::<bitcoin::PublicKey>::from_str(&descriptor)
        .expect("a valid descriptor");

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
