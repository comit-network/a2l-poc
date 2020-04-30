use crate::bitcoin;
use crate::puzzle_promise::{Message0, Message1, Message2, Message3};
use crate::Params;
use crate::{hsm_cl, secp256k1, Lock};
use ::bitcoin::hashes::Hash;
use rand::Rng;

pub struct Receiver0 {
    x_r: secp256k1::KeyPair,
    params: Params,
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
