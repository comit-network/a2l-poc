use crate::bitcoin;
use crate::Params;
use crate::{hsm_cl, secp256k1, Lock};
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
    signed_refund_transaction: bitcoin::Transaction,
    transactions: bitcoin::Transactions,
}

pub struct Receiver1 {
    x_r: secp256k1::KeyPair,
    X_t: secp256k1::PublicKey,
    c_alpha: hsm_cl::Ciphertext,
    A: secp256k1::PublicKey,
    transactions: bitcoin::Transactions,
}

#[derive(Debug)]
pub struct Receiver2 {
    x_r: secp256k1::KeyPair,
    X_t: secp256k1::PublicKey,
    beta: secp256k1::KeyPair,
    c_alpha_prime: hsm_cl::Ciphertext,
    A_prime: secp256k1::PublicKey,
    sig_redeem_r: secp256k1::Signature,
    sig_redeem_t: secp256k1::EncryptedSignature,
    transactions: bitcoin::Transactions,
}

impl Receiver0 {
    pub fn new(params: Params, rng: &mut impl Rng) -> Self {
        Self {
            x_r: secp256k1::KeyPair::random(rng),
            params,
        }
    }

    pub fn receive(
        self,
        Message0 {
            X_t,
            c_alpha,
            pi_alpha,
            A,
        }: Message0,
        HE: &impl hsm_cl::Verify,
    ) -> anyhow::Result<Receiver1> {
        let Receiver0 { x_r, params } = self;

        let statement = (&c_alpha, &A);
        HE.verify(&pi_alpha, statement)?;

        let transactions = bitcoin::make_transactions(
            params.partial_fund_transaction.clone(),
            params.tumbler_receiver_joint_output_value(),
            params.tumbler_receiver_joint_output_takeout(),
            &X_t,
            &x_r.to_pk(),
            params.expiry,
            &params.redeem_identity,
            &params.refund_identity,
        );

        Ok(Receiver1 {
            x_r,
            X_t,
            c_alpha,
            A,
            transactions,
        })
    }
}

impl Receiver1 {
    pub fn next_message(&self) -> Message1 {
        let sig_refund_r = secp256k1::sign(self.transactions.refund_tx_digest, &self.x_r);

        Message1 {
            X_r: self.x_r.to_pk(),
            sig_refund_r,
        }
    }

    pub fn receive(
        self,
        Message2 { sig_redeem_t }: Message2,
        rng: &mut impl Rng,
    ) -> anyhow::Result<Receiver2> {
        let Self {
            x_r,
            X_t,
            A,
            c_alpha,
            transactions,
        } = self;

        secp256k1::encverify(
            &X_t,
            &A,
            &transactions.redeem_tx_digest.into_inner(),
            &sig_redeem_t,
        )?;

        let sig_redeem_r = secp256k1::sign(transactions.redeem_tx_digest, &x_r);

        let beta = secp256k1::KeyPair::random(rng);
        let c_alpha_prime = &c_alpha * &beta;
        let A_prime = {
            let mut A_prime = A;
            A_prime.tweak_mul_assign(beta.as_sk()).unwrap();
            A_prime
        };

        Ok(Receiver2 {
            x_r,
            X_t,
            beta,
            c_alpha_prime,
            A_prime,
            sig_redeem_r,
            sig_redeem_t,
            transactions,
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
        let (c_alpha, pi_alpha) = HE.encrypt(&self.a);

        Message0 {
            X_t,
            A,
            c_alpha,
            pi_alpha,
        }
    }

    pub fn receive(self, Message1 { X_r, sig_refund_r }: Message1) -> anyhow::Result<Tumbler1> {
        let transactions = bitcoin::make_transactions(
            self.params.partial_fund_transaction.clone(),
            self.params.tumbler_receiver_joint_output_value(),
            self.params.tumbler_receiver_joint_output_takeout(),
            &self.x_t.to_pk(),
            &X_r,
            self.params.expiry,
            &self.params.redeem_identity,
            &self.params.refund_identity,
        );

        let signed_refund_transaction = {
            secp256k1::verify(transactions.refund_tx_digest, &sig_refund_r, &X_r)
                .context("failed to verify receiver refund signature")?;

            let sig_refund_t = secp256k1::sign(transactions.refund_tx_digest, &self.x_t);

            bitcoin::complete_spend_transaction(
                transactions.refund.clone(),
                (self.x_t.to_pk(), sig_refund_t),
                (X_r, sig_refund_r),
            )?
        };

        Ok(Tumbler1 {
            x_t: self.x_t,
            signed_refund_transaction,
            a: self.a,
            transactions,
        })
    }
}

impl Tumbler1 {
    pub fn next_message(&self, rng: &mut impl Rng) -> Message2 {
        let sig_redeem_t = secp256k1::encsign(
            self.transactions.redeem_tx_digest,
            &self.x_t,
            &self.a.to_pk(),
            rng,
        );

        Message2 { sig_redeem_t }
    }

    pub fn unsigned_fund_transaction(&self) -> &bitcoin::Transaction {
        &self.transactions.fund
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
        &self.transactions.redeem
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
    pub fn redeem_tx_digest(&self) -> &bitcoin::SigHash {
        &self.transactions.redeem_tx_digest
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

#[cfg(test)]
mod test {
    use super::*;

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
