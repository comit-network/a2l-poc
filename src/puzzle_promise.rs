use crate::{hsm_cl, secp256k1, Lock};

mod receiver;
mod sender;
mod tumbler;

pub use receiver::{Receiver0, Receiver1, Receiver2};
pub use sender::{Sender0, Sender1};
pub use tumbler::{Tumbler0, Tumbler1};

pub struct Message0 {
    X_t: secp256k1::PublicKey,
    A: secp256k1::PublicKey,
    c_alpha: hsm_cl::Ciphertext,
    pi_alpha: hsm_cl::Proof,
}

pub struct Message1 {
    X_r: secp256k1::PublicKey,
    sig_refund_r: secp256k1::Signature,
}

pub struct Message2 {
    sig_redeem_t: secp256k1::EncryptedSignature,
}

pub struct Message3 {
    l: Lock,
}

pub enum Message {
    Message0(Message0),
    Message1(Message1),
    Message2(Message2),
    Message3(Message3),
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bitcoin;
    use crate::Params;

    macro_rules! run_protocol {
        ($rng:ident, $receiver:ident, $tumbler:ident, $sender:ident, $HE_keypair:ident, $HE_pk:ident) => {
            let message = $tumbler.next_message(&$HE_keypair.to_pk());
            let $receiver = $receiver.receive(message, &$HE_pk).unwrap();
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

        let tumble_amount = 10_000_000;
        let spend_transaction_fee_per_wu = 10;
        let params = Params::new(
            bitcoin::random_p2wpkh(),
            bitcoin::random_p2wpkh(),
            0,
            tumble_amount,
            0,
            spend_transaction_fee_per_wu,
            bitcoin::Transaction {
                lock_time: 0,
                version: 2,
                input: Vec::new(),
                output: vec![bitcoin::TxOut {
                    value: tumble_amount
                        + bitcoin::MAX_SATISFACTION_WEIGHT * spend_transaction_fee_per_wu,
                    script_pubkey: Default::default(),
                }],
            },
        );

        let receiver = Receiver0::new(params.clone(), &mut rng);
        let tumbler = Tumbler0::new(params, &mut rng);
        let sender = Sender0::new();

        run_protocol!(rng, receiver, tumbler, sender, keypair, publickey);
    }

    #[test]
    #[should_panic]
    fn protocol_fails_if_parameters_differ() {
        let mut rng = rand::thread_rng();
        let keypair = hsm_cl::keygen(b"A2L-PoC");
        let publickey = keypair.to_pk();

        let tumble_amount = 10_000_000;
        let spend_transaction_fee_per_wu = 10;
        let params = Params::new(
            bitcoin::random_p2wpkh(),
            bitcoin::random_p2wpkh(),
            0,
            tumble_amount,
            0,
            spend_transaction_fee_per_wu,
            bitcoin::Transaction {
                lock_time: 0,
                version: 2,
                input: Vec::new(),
                output: vec![bitcoin::TxOut {
                    value: tumble_amount
                        + bitcoin::MAX_SATISFACTION_WEIGHT * spend_transaction_fee_per_wu,
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
        );
        let tumbler = Tumbler0::new(params, &mut rng);
        let sender = Sender0::new();

        run_protocol!(rng, receiver, tumbler, sender, keypair, publickey);
    }
}
