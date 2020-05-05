use crate::{hsm_cl, secp256k1, Lock};

mod receiver;
mod sender;
mod tumbler;

pub use receiver::{Receiver0, Receiver1, Receiver2};
pub use sender::{Sender0, Sender1};
pub use tumbler::{Tumbler, Tumbler0, Tumbler1};

#[derive(Debug, serde::Serialize)]
pub struct Message0 {
    #[serde(with = "crate::serde::secp256k1_public_key")]
    pub X_t: secp256k1::PublicKey,
    #[serde(with = "crate::serde::secp256k1_public_key")]
    pub A: secp256k1::PublicKey,
    pub c_alpha: hsm_cl::Ciphertext,
    pub pi_alpha: hsm_cl::Proof,
}

#[derive(Debug, serde::Serialize)]
pub struct Message1 {
    #[serde(with = "crate::serde::secp256k1_public_key")]
    pub X_r: secp256k1::PublicKey,
    #[serde(with = "crate::serde::secp256k1_signature")]
    pub sig_refund_r: secp256k1::Signature,
}

#[derive(Debug, serde::Serialize)]
pub struct Message2 {
    pub sig_redeem_t: secp256k1::EncryptedSignature,
}

#[derive(Debug, derive_more::From)]
pub enum Message {
    Message0(Message0),
    Message1(Message1),
    Message2(Message2),
    Message3(Message3),
}

#[derive(Debug, serde::Serialize)]
pub struct Message3 {
    pub l: Lock,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bitcoin;
    use crate::Params;

    macro_rules! run_protocol {
        ($rng:ident, $receiver:ident, $tumbler:ident, $sender:ident) => {
            let message = $tumbler.next_message();
            let $receiver = $receiver.receive(message).unwrap();
            let message = $receiver.next_message();
            let $tumbler = $tumbler.receive(message).unwrap();
            let message = $tumbler.next_message(&mut $rng);
            let $receiver = $receiver.receive(message, &mut $rng).unwrap();
            let message = $receiver.next_message();
            #[allow(unused_variables)]
            let $sender = $sender.receive(message);
        };
    }

    #[test]
    fn happy_path() {
        let mut rng = rand::thread_rng();
        let keypair = hsm_cl::keygen(b"A2L-PoC");
        let publickey = keypair.to_pk();

        let tumble_amount = bitcoin::Amount::from_sat(10_000_000);
        let spend_transaction_fee_per_wu = bitcoin::Amount::from_sat(10);
        let params = Params::new(
            bitcoin::random_p2wpkh(),
            bitcoin::random_p2wpkh(),
            0,
            tumble_amount,
            bitcoin::Amount::from_sat(0),
            spend_transaction_fee_per_wu,
            bitcoin::Transaction {
                lock_time: 0,
                version: 2,
                input: Vec::new(),
                output: vec![bitcoin::TxOut {
                    value: (tumble_amount
                        + spend_transaction_fee_per_wu * bitcoin::MAX_SATISFACTION_WEIGHT)
                        .as_sat(),
                    script_pubkey: Default::default(),
                }],
            },
        );

        let receiver = Receiver0::new(params.clone(), &mut rng, publickey);
        let tumbler = Tumbler0::new(params, keypair, &mut rng);
        let sender = Sender0::new();

        run_protocol!(rng, receiver, tumbler, sender);
    }

    #[test]
    #[should_panic]
    fn protocol_fails_if_parameters_differ() {
        let mut rng = rand::thread_rng();
        let keypair = hsm_cl::keygen(b"A2L-PoC");
        let publickey = keypair.to_pk();

        let tumble_amount = bitcoin::Amount::from_sat(10_000_000);
        let spend_transaction_fee_per_wu = bitcoin::Amount::from_sat(10);
        let params = Params::new(
            bitcoin::random_p2wpkh(),
            bitcoin::random_p2wpkh(),
            0,
            tumble_amount,
            bitcoin::Amount::from_sat(0),
            spend_transaction_fee_per_wu,
            bitcoin::Transaction {
                lock_time: 0,
                version: 2,
                input: Vec::new(),
                output: vec![bitcoin::TxOut {
                    value: (tumble_amount
                        + spend_transaction_fee_per_wu * bitcoin::MAX_SATISFACTION_WEIGHT)
                        .as_sat(),
                    script_pubkey: Default::default(),
                }],
            },
        );

        let receiver = Receiver0::new(
            Params {
                redeem_identity: bitcoin::random_p2wpkh(),
                ..params.clone()
            },
            &mut rng,
            publickey,
        );
        let tumbler = Tumbler0::new(params, keypair, &mut rng);
        let sender = Sender0::new();

        run_protocol!(rng, receiver, tumbler, sender);
    }
}
