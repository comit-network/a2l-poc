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
//
// pub async fn new_tumbler(
//     params: Params,
//     mut rng: impl Rng,
//     HE: impl hsm_cl::Encrypt,
//     mut incoming: tokio::sync::mpsc::Receiver<tumbler::In>,
//     mut outgoing: tokio::sync::mpsc::Sender<tumbler::Out>,
// ) -> anyhow::Result<tumbler::Return> {
//     let tumbler = Tumbler0::new(params, rng);
//
//     outgoing
//         .send(tumbler::Out::Message0(tumbler.next_message(&HE)))
//         .await;
//
//     let message = match incoming.recv().await {
//         Some(tumbler::In::Message1(message)) => mesage,
//         _ => anyhow::bail!(UnexpectedMessage),
//     };
//
//     let tumbler = tumbler.receive(message)?;
//     outgoing
//         .send(tumbler::Out::Message2(tumbler.next_message(&mut rng)))
//         .await;
//
//     Ok(tumbler.into())
// }

// pub async fn new_receiver(
//     params: Params,
//     mut rng: impl Rng,
//     HE: impl hsm_cl::Verify,
//     mut incoming: tokio::sync::mpsc::Receiver<receiver::In>,
//     mut outgoing: tokio::sync::mpsc::Sender<receiver::Out>,
// ) -> anyhow::Result<tumbler::Return> {
//     let receiver = Receiver0::new(params, rng);
//
//     let message = match incoming.recv().await {
//         Some(receiver::In::Message0(message)) => message,
//         _ => anyhow::bail!(UnexpectedMessage),
//     };
//
//     let receiver = receiver.receive(message, &HE)?;
//
//     outgoing
//         .send(receiver::Out::Message1(receiver.next_message()))
//         .await;
//
//     let message = match incoming.recv().await {
//         Some(receiver::In::Message2(message)) => mesage,
//         _ => anyhow::bail!(UnexpectedMessage),
//     };
//
//     let receiver = receiver.receive(message, &mut rng)?;
//
//     outgoing
//         .send(receiver::Out::Message3(receiver.next_message()))
//         .await;
//
//     Ok(receiver.into())
// }

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
