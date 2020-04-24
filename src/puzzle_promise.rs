use crate::bitcoin;
use crate::Params;
use crate::{dummy_hsm_cl as hsm_cl, secp256k1, Lock};
use ::bitcoin::hashes::Hash;
use anyhow::Context;
use rand::Rng;

pub struct Tumbler0 {
    x_t: secp256k1::KeyPair,
    a: secp256k1::KeyPair,
    params: Params,
}

pub struct Sender0;

pub struct Receiver0 {
    x_r: secp256k1::KeyPair,
    params: Params,
}

#[derive(Debug)]
pub struct Sender1 {
    l: Lock,
}

#[derive(Debug)]
pub struct Tumbler1 {
    x_t: secp256k1::KeyPair,
    a: secp256k1::KeyPair,
    unsigned_fund_transaction: bitcoin::Transaction,
    signed_refund_transaction: bitcoin::Transaction,
    redeem_amount: u64,
    redeem_identity: bitcoin::Address,
}

pub struct Receiver1 {
    x_r: secp256k1::KeyPair,
    X_t: secp256k1::PublicKey,
    c_alpha: hsm_cl::Ciphertext,
    A: secp256k1::PublicKey,
    fund_transaction: bitcoin::Transaction,
    redeem_identity: bitcoin::Address,
    refund_identity: bitcoin::Address,
    expiry: u32,
    amount: u64,
}

#[derive(Debug)]
pub struct Receiver2 {
    x_r: secp256k1::KeyPair,
    X_t: secp256k1::PublicKey,
    beta: secp256k1::KeyPair,
    c_alpha_prime: hsm_cl::Ciphertext,
    A_prime: secp256k1::PublicKey,
    unsigned_redeem_transaction: bitcoin::Transaction,
    sig_redeem_r: secp256k1::Signature,
    sig_redeem_t: secp256k1::EncryptedSignature,
}

impl Receiver0 {
    pub fn new(params: Params, rng: &mut impl Rng) -> Self {
        Self {
            x_r: secp256k1::KeyPair::random(rng),
            params,
        }
    }

    pub fn receive(self, Message0 { X_t, c_alpha, A }: Message0) -> anyhow::Result<Receiver1> {
        let Receiver0 {
            x_r,
            params:
                Params {
                    redeem_identity,
                    refund_identity,
                    expiry,
                    partial_fund_transaction: fund_transaction,
                    tumble_amount: amount,
                    ..
                },
        } = self;

        // TODO: Verify c_alpha with pi_alpha (line 8, Figure 6)

        // TODO: account for fee in these amounts

        let fund_transaction =
            bitcoin::make_fund_transaction(fund_transaction, amount, &X_t, &x_r.to_pk());

        Ok(Receiver1 {
            x_r,
            X_t,
            fund_transaction,
            c_alpha,
            A,
            redeem_identity,
            refund_identity,
            expiry,
            amount,
        })
    }
}

impl Receiver1 {
    pub fn next_message(&self) -> Message1 {
        let (_, digest) = bitcoin::make_spend_transaction(
            &self.fund_transaction,
            self.amount,
            &self.refund_identity,
            self.expiry,
        );
        let sig_refund_r = secp256k1::sign(digest, &self.x_r);

        Message1 {
            X_r: self.x_r.to_pk(),
            sig_refund_r,
        }
    }

    pub fn receive<HE>(
        self,
        Message2 { sig_redeem_t }: Message2,
        rng: &mut impl Rng,
        HE: &HE,
    ) -> anyhow::Result<Receiver2>
    where
        HE: hsm_cl::Pow<secp256k1::PublicKey> + hsm_cl::Pow<hsm_cl::Ciphertext>,
    {
        let Self {
            x_r,
            X_t,
            A,
            amount,
            redeem_identity,
            fund_transaction,
            c_alpha,
            ..
        } = self;

        let (unsigned_redeem_transaction, digest) =
            bitcoin::make_spend_transaction(&fund_transaction, amount, &redeem_identity, 0);

        secp256k1::encverify(&X_t, &A, &digest.into_inner(), &sig_redeem_t)?;

        let sig_redeem_r = secp256k1::sign(digest, &x_r);

        let beta = secp256k1::KeyPair::random(rng);
        let c_alpha_prime = HE.pow(&c_alpha, &beta);
        let A_prime = HE.pow(&A, &beta);

        Ok(Receiver2 {
            x_r,
            X_t,
            beta,
            c_alpha_prime,
            A_prime,
            sig_redeem_r,
            sig_redeem_t,
            unsigned_redeem_transaction,
        })
    }
}

impl Tumbler0 {
    pub fn new(params: Params, rng: &mut impl Rng) -> Self {
        let x_t = secp256k1::KeyPair::random(rng);
        let a = secp256k1::KeyPair::random(rng);

        Self { x_t, a, params }
    }

    pub fn next_message(&self, HE: &impl hsm_cl::Encrypt) -> Message0 {
        let X_t = self.x_t.to_pk();
        let A = self.a.to_pk();
        let c_alpha = HE.encrypt(&self.x_t, self.a.as_ref());

        // TODO: Compute pi_alpha (line 4, Figure 6)

        Message0 { X_t, A, c_alpha }
    }

    pub fn receive(self, Message1 { X_r, sig_refund_r }: Message1) -> anyhow::Result<Tumbler1> {
        let unsigned_fund_transaction = bitcoin::make_fund_transaction(
            self.params.partial_fund_transaction,
            self.params.tumble_amount,
            &self.x_t.to_pk(),
            &X_r,
        );

        let signed_refund_transaction = {
            let (transaction, digest) = bitcoin::make_spend_transaction(
                &unsigned_fund_transaction,
                self.params.tumble_amount,
                &self.params.refund_identity,
                self.params.expiry,
            );

            secp256k1::verify(digest, &sig_refund_r, &X_r)
                .context("failed to verify receiver refund signature")?;

            let sig_refund_t = secp256k1::sign(digest, &self.x_t);

            bitcoin::complete_spend_transaction(
                transaction,
                (self.x_t.to_pk(), sig_refund_t),
                (X_r, sig_refund_r),
            )?
        };

        Ok(Tumbler1 {
            x_t: self.x_t,
            unsigned_fund_transaction,
            signed_refund_transaction,
            a: self.a,
            redeem_amount: self.params.tumble_amount, // TODO: Handle fee
            redeem_identity: self.params.redeem_identity,
        })
    }
}

impl Tumbler1 {
    pub fn next_message(&self, rng: &mut impl Rng) -> Message2 {
        let (_, digest) = bitcoin::make_spend_transaction(
            &self.unsigned_fund_transaction,
            self.redeem_amount,
            &self.redeem_identity,
            0,
        );
        let sig_redeem_t = secp256k1::encsign(digest, &self.x_t, &self.a.to_pk(), rng);

        Message2 { sig_redeem_t }
    }

    pub fn unsigned_fund_transaction(&self) -> &bitcoin::Transaction {
        &self.unsigned_fund_transaction
    }
    pub fn signed_refund_transaction(&self) -> &bitcoin::Transaction {
        &self.signed_refund_transaction
    }
    pub fn x_t(&self) -> &secp256k1::KeyPair {
        &self.x_t
    }
}

impl Receiver2 {
    pub fn next_message(&self) -> Message3 {
        let l = Lock {
            c_alpha_prime: self.c_alpha_prime.clone(),
            A_prime: self.A_prime.clone(),
        };

        Message3 { l }
    }

    pub fn x_r(&self) -> &secp256k1::KeyPair {
        &self.x_r
    }
    pub fn X_t(&self) -> &secp256k1::PublicKey {
        &self.X_t
    }
    pub fn unsigned_redeem_transaction(&self) -> &bitcoin::Transaction {
        &self.unsigned_redeem_transaction
    }
    pub fn sig_redeem_t(&self) -> &secp256k1::EncryptedSignature {
        &self.sig_redeem_t
    }
    pub fn sig_redeem_r(&self) -> &secp256k1::Signature {
        &self.sig_redeem_r
    }
    pub fn beta(&self) -> &secp256k1::KeyPair {
        &self.beta
    }
}

impl Sender0 {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self
    }

    pub fn receive(self, message: Message3) -> Sender1 {
        Sender1 { l: message.l }
    }
}

impl Sender1 {
    pub fn lock(&self) -> &Lock {
        &self.l
    }
}

pub struct Message0 {
    X_t: secp256k1::PublicKey,
    A: secp256k1::PublicKey,
    c_alpha: hsm_cl::Ciphertext,
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

// #[cfg(test)]
// mod test {
//     use super::*;

//     macro_rules! run_protocol {
//         ($rng:ident, $receiver:ident, $tumbler:ident, $sender:ident, $HE_sk:ident, $HE_pk:ident) => {
//             let message = $tumbler.next_message(&$HE_sk);
//             let $receiver = $receiver.receive(message).unwrap();
//             let message = $receiver.next_message();
//             let $tumbler = $tumbler.receive(message).unwrap();
//             let message = $tumbler.next_message(&mut $rng);
//             let $receiver = $receiver.receive(message, &mut $rng, &$HE_pk).unwrap();
//             let message = $receiver.next_message();
//             #[allow(unused_variables)]
//             let $sender = $sender.receive(message);
//         };
//     }

//     #[test]
//     fn happy_path() {
//         let mut rng = rand::thread_rng();
//         let (secretkey, publickey) = hsm_cl::keygen();

//         let params = make_params(&mut rng);

//         let receiver = Receiver0::new(params.clone(), &mut rng);
//         let tumbler = Tumbler0::new(params, &mut rng);
//         let sender = Sender0::new();

//         run_protocol!(rng, receiver, tumbler, sender, secretkey, publickey);
//     }

//     #[test]
//     #[should_panic]
//     fn protocol_fails_if_parameters_differ() {
//         let mut rng = rand::thread_rng();
//         let (secretkey, publickey) = hsm_cl::keygen();

//         let params = make_params(&mut rng);

//         let receiver = Receiver0::new(
//             Params {
//                 amount: params.amount / 2,
//                 ..params.clone()
//             },
//             &mut rng,
//         );
//         let tumbler = Tumbler0::new(params, &mut rng);
//         let sender = Sender0::new();

//         run_protocol!(rng, receiver, tumbler, sender, secretkey, publickey);
//     }

//     fn make_params(mut rng: &mut impl Rng) -> Params {
//         let redeem_identity = secp256k1::SecretKey::random(&mut rng);
//         let refund_identity = secp256k1::SecretKey::random(&mut rng);

//         Params {
//             redeem_identity: bitcoin::Address::p2wpkh(
//                 bitcoin::secp256k1::PublicKey::from_secret_key(&redeem_identity),
//                 ::bitcoin::Network::Regtest,
//             ),
//             refund_identity: bitcoin::Address::p2wpkh(
//                 bitcoin::secp256k1::PublicKey::from_secret_key(&refund_identity),
//                 ::bitcoin::Network::Regtest,
//             ),
//             expiry: 0,
//             amount: 10000,
//             partial_fund_transaction: bitcoin::Transaction {
//                 lock_time: 0,
//                 version: 2,
//                 input: Vec::new(), // TODO: fill these from a `fundrawtransaction` call
//                 output: Vec::new(), // TODO: fill these from a `fundrawtransaction` call
//             },
//         }
//     }
// }
