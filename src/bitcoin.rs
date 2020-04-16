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
    let input = TxIn {
        previous_output: joint_outpoint,
        script_sig: Script::new(), // this is empty because it is a witness transaction
        sequence: 0xFFFF_FFFF,     // TODO: What is the ideal sequence for the redeem tx?
        witness: Vec::new(),       // this is empty because we cannot generate the signatures yet
    };
    let output = make_spend_output(redeem_amount, redeem_identity);

    bitcoin::Transaction {
        version: 2,
        lock_time: 0,
        input: vec![input],
        output: vec![output],
    }
}

pub fn make_refund_signature<S: AsRef<secp256k1::SecretKey>, C: secp256k1::Signing>(
    joint_outpoint: OutPoint,
    joint_output: TxOut,
    expiry: u32,
    refund_amount: u64,
    refund_identity: &secp256k1::PublicKey,
    x: &S,
    context: &secp256k1::Secp256k1<C>,
) -> secp256k1::Signature {
    let input = make_refund_input(joint_outpoint);
    let output = make_spend_output(refund_amount, refund_identity);

    let refund_transaction = bitcoin::Transaction {
        version: 2,
        lock_time: expiry,
        input: vec![input.clone()],
        output: vec![output],
    };

    let refund_digest = SighashComponents::new(&refund_transaction).sighash_all(
        &input,
        &joint_output.script_pubkey,
        joint_output.value,
    );
    let refund_digest = secp256k1::Message::from_slice(&refund_digest.into_inner())
        .expect("should not fail because it is a hash");

    context.sign(&refund_digest, x.as_ref())
}

pub fn make_refund_input(joint_outpoint: OutPoint) -> TxIn {
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
    let X_1 = format!("{:x}", X_1);
    let X_2 = format!("{:x}", X_2);

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
            key: *identity,
        },
        network,
    )
    .script_pubkey()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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

    fn compressed_public_key(
    ) -> impl Strategy<Value = Result<secp256k1::PublicKey, secp256k1::Error>> {
        "02[0-9a-f]{64}".prop_map(|hex| secp256k1::PublicKey::from_str(&hex))
    }

    proptest! {
        #[test]
        fn given_any_network_results_in_the_same_script_pubkey(public_key in compressed_public_key()) {
            let public_key = match public_key {
                Ok(public_key) => public_key,
                _ => return Err(TestCaseError::Reject("generated invalid public key".into()))
            };

            let mainnet_script_pubkey = make_p2wpkh_script_pubkey(&public_key, bitcoin::Network::Bitcoin);
            let testnet_script_pubkey = make_p2wpkh_script_pubkey(&public_key, bitcoin::Network::Testnet);
            let regtest_script_pubkey = make_p2wpkh_script_pubkey(&public_key, bitcoin::Network::Regtest);

            assert_eq!(mainnet_script_pubkey, testnet_script_pubkey);
            assert_eq!(testnet_script_pubkey, regtest_script_pubkey);
        }
    }

    proptest! {
        #[test]
        fn any_two_public_keys_yield_a_valid_descriptor(value: u64, X_1 in compressed_public_key(), X_2 in compressed_public_key()) {
            let (X_1, X_2) = match (X_1, X_2) {
                (Ok(X_1), Ok(X_2)) => (X_1, X_2),
                _ => return Err(TestCaseError::Reject("generated invalid public key".into()))
            };

            make_fund_output(value, &X_1, &X_2)
        }
    }
}
