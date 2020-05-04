use crate::puzzle_solver::{Message, Message0, Message1, Message2, Message3, Message4};
use crate::secp256k1;
use crate::Lock;
use crate::Params;
use crate::{bitcoin, UnexpectedMessage};
use crate::{hsm_cl, NoMessage};
use anyhow::Context as _;
use rand::Rng;
use std::convert::TryInto;

#[derive(Debug, derive_more::From)]
pub enum Sender {
    Sender0(Sender0),
    Sender1(Sender1),
    Sender2(Sender2),
    Sender3(Sender3),
}

impl Sender {
    pub fn new(params: Params, lock: Lock, rng: &mut impl Rng) -> Self {
        let sender = Sender0::new(params, lock, rng);

        sender.into()
    }

    pub fn transition(self, message: Message, rng: &mut impl Rng) -> anyhow::Result<Self> {
        let sender = match (self, message) {
            (Sender::Sender0(inner), Message::Message0(message)) => {
                inner.receive(message, rng).into()
            }
            (Sender::Sender1(inner), Message::Message2(message)) => {
                inner.receive(message, rng)?.into()
            }
            // (Sender::Sender2(inner), In::RedeemTransaction(transaction)) => {
            //     inner.receive(transaction)?.into()
            // }
            _ => anyhow::bail!(UnexpectedMessage),
        };

        Ok(sender)
    }

    pub fn next_message(&self) -> Result<Message, NoMessage> {
        let message = match self {
            Sender::Sender1(inner) => inner.next_message().into(),
            Sender::Sender2(inner) => inner.next_message().into(),
            Sender::Sender3(inner) => inner.next_message().into(),
            _ => return Err(NoMessage),
        };

        Ok(message)
    }
}

#[derive(Debug)]
pub struct Sender0 {
    params: Params,
    x_s: secp256k1::KeyPair,
    c_alpha_prime: hsm_cl::Ciphertext,
    A_prime: secp256k1::PublicKey,
}

#[derive(Debug)]
pub struct Sender1 {
    params: Params,
    x_s: secp256k1::KeyPair,
    X_t: secp256k1::PublicKey,
    c_alpha_prime: hsm_cl::Ciphertext,
    A_prime: secp256k1::PublicKey,
    tau: secp256k1::KeyPair,
}

#[derive(Debug)]
pub struct Sender2 {
    unsigned_fund_transaction: bitcoin::Transaction,
    signed_refund_transaction: bitcoin::Transaction,
    sig_redeem_s: secp256k1::EncryptedSignature,
    A_prime_prime: secp256k1::PublicKey,
    x_s: secp256k1::KeyPair,
    tau: secp256k1::KeyPair,
    redeem_tx_digest: bitcoin::SigHash,
}

#[derive(Debug)]
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
    pub fn next_message(&self) -> Message1 {
        let c_alpha_prime_prime = &self.c_alpha_prime * &self.tau;

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
    ) -> anyhow::Result<Sender2> {
        let A_prime_tau = {
            let mut A_prime_tau = self.A_prime.clone();
            A_prime_tau.tweak_mul_assign(self.tau.as_sk()).unwrap();
            A_prime_tau
        };
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
            let tau: secp256k1::Scalar = tau.into_sk().into();

            gamma * tau.inv()
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
