use crate::bitcoin;
use crate::dummy_hsm_cl as hsm_cl;
use crate::puzzle_solver::{Message0, Message1, Message2, Message3, Message4};
use crate::secp256k1;
use crate::Lock;
use crate::Params;
use anyhow::Context as _;
use rand::Rng;
use std::convert::TryInto;

pub struct Sender0 {
    params: Params,
    x_s: secp256k1::KeyPair,
    c_alpha_prime: hsm_cl::Ciphertext,
    A_prime: secp256k1::PublicKey,
}

pub struct Sender1 {
    params: Params,
    x_s: secp256k1::KeyPair,
    X_t: secp256k1::PublicKey,
    c_alpha_prime: hsm_cl::Ciphertext,
    A_prime: secp256k1::PublicKey,
    tau: secp256k1::KeyPair,
}

pub struct Sender2 {
    unsigned_fund_transaction: bitcoin::Transaction,
    signed_refund_transaction: bitcoin::Transaction,
    sig_redeem_s: secp256k1::EncryptedSignature,
    A_prime_prime: secp256k1::PublicKey,
    x_s: secp256k1::KeyPair,
    tau: secp256k1::KeyPair,
    redeem_tx_digest: bitcoin::SigHash,
}

pub struct Sender3 {
    alpha_macron: secp256k1::KeyPair,
    signed_refund_transaction: bitcoin::Transaction,
}

#[derive(thiserror::Error, Debug)]
#[error("(A')^tau != A''")]
pub struct AptNotEqualApp;

impl Sender0 {
    pub fn new(
        params: Params,
        Lock {
            c_alpha_prime,
            A_prime,
        }: Lock,
        rng: &mut impl Rng,
    ) -> Self {
        Self {
            params,
            x_s: secp256k1::KeyPair::random(rng),
            c_alpha_prime,
            A_prime,
        }
    }

    pub fn receive(self, Message0 { X_t }: Message0, rng: &mut impl Rng) -> Sender1 {
        Sender1 {
            params: self.params,
            x_s: self.x_s,
            X_t,
            c_alpha_prime: self.c_alpha_prime,
            A_prime: self.A_prime,
            tau: secp256k1::KeyPair::random(rng),
        }
    }
}

impl Sender1 {
    pub fn next_message(&self, HE: &impl hsm_cl::Pow<hsm_cl::Ciphertext>) -> Message1 {
        let c_alpha_prime_prime = HE.pow(&self.c_alpha_prime, &self.tau);

        Message1 {
            c_alpha_prime_prime,
            X_s: self.x_s.to_pk(),
        }
    }

    pub fn receive(
        self,
        Message2 {
            A_prime_prime,
            sig_refund_t,
        }: Message2,
        rng: &mut impl Rng,
        HE: &impl hsm_cl::Pow<secp256k1::PublicKey>,
    ) -> anyhow::Result<Sender2> {
        let A_prime_tau = HE.pow(&self.A_prime, &self.tau);
        if A_prime_tau != A_prime_prime {
            anyhow::bail!(AptNotEqualApp)
        }

        let transactions = bitcoin::make_transactions(
            self.params.partial_fund_transaction.clone(),
            self.params.sender_tumbler_joint_output_value(),
            self.params.sender_tumbler_joint_output_takeout(),
            &self.x_s.to_pk(),
            &self.X_t,
            self.params.expiry,
            &self.params.redeem_identity,
            &self.params.refund_identity,
        );

        let sig_refund_s = {
            secp256k1::verify(transactions.refund_tx_digest, &sig_refund_t, &self.X_t)
                .context("failed to verify tumbler refund signature")?;

            secp256k1::sign(transactions.refund_tx_digest, &self.x_s)
        };

        let sig_redeem_s = secp256k1::encsign(
            transactions.redeem_tx_digest,
            &self.x_s,
            &A_prime_prime,
            rng,
        );

        Ok(Sender2 {
            unsigned_fund_transaction: transactions.fund,
            signed_refund_transaction: bitcoin::complete_spend_transaction(
                transactions.refund,
                (self.x_s.to_pk(), sig_refund_s),
                (self.X_t.clone(), sig_refund_t),
            )?,
            sig_redeem_s,
            A_prime_prime,
            x_s: self.x_s,
            tau: self.tau,
            redeem_tx_digest: transactions.redeem_tx_digest,
        })
    }
}

impl Sender2 {
    pub fn next_message(&self) -> Message3 {
        Message3 {
            sig_redeem_s: self.sig_redeem_s.clone(),
        }
    }

    pub fn receive(self, redeem_transaction: bitcoin::Transaction) -> anyhow::Result<Sender3> {
        let Self {
            sig_redeem_s: encrypted_signature,
            A_prime_prime,
            tau,
            signed_refund_transaction,
            ..
        } = self;

        let decrypted_signature = bitcoin::extract_signature_by_key(
            redeem_transaction,
            self.redeem_tx_digest,
            &self.x_s.to_pk(),
        )?;

        let gamma =
            secp256k1::recover(&A_prime_prime, &encrypted_signature, &decrypted_signature)??;
        let alpha_macron = {
            let gamma: secp256k1::Scalar = gamma.into_sk().into();
            // let tau: secp256k1::Scalar = tau.into_sk().into();

            // gamma * tau.inv()
            gamma
        };

        Ok(Sender3 {
            alpha_macron: alpha_macron.try_into()?,
            signed_refund_transaction,
        })
    }

    pub fn unsigned_fund_transaction(&self) -> bitcoin::Transaction {
        self.unsigned_fund_transaction.clone()
    }

    pub fn signed_refund_transaction(&self) -> bitcoin::Transaction {
        self.signed_refund_transaction.clone()
    }
}

impl Sender3 {
    pub fn next_message(&self) -> Message4 {
        Message4 {
            alpha_macron: self.alpha_macron.to_sk(),
        }
    }

    pub fn alpha_macron(&self) -> &secp256k1::KeyPair {
        &self.alpha_macron
    }

    pub fn signed_refund_transaction(&self) -> &bitcoin::Transaction {
        &self.signed_refund_transaction
    }
}
