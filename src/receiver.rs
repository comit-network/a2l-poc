use crate::{
    bitcoin, hsm_cl, puzzle_promise, puzzle_solver, secp256k1, Lock, NoMessage, NoTransaction,
    Params, UnexpectedMessage,
};
use ::bitcoin::hashes::Hash;
use anyhow::{bail, Context};
use rand::Rng;
use std::convert::TryFrom;

#[derive(Debug, derive_more::From, Clone)]
pub enum Receiver {
    Receiver0(Receiver0),
    Receiver1(Receiver1),
    Receiver2(Receiver2),
    Receiver3(Receiver3),
}

impl Receiver {
    pub fn new(params: Params, rng: &mut impl Rng, HE: hsm_cl::PublicKey) -> Self {
        let receiver0 = Receiver0::new(params, rng, HE);

        receiver0.into()
    }

    pub fn transition_on_puzzle_promise_message(
        self,
        message: puzzle_promise::Message,
        rng: &mut impl Rng,
    ) -> anyhow::Result<Self> {
        let receiver = match (self, message) {
            (Receiver::Receiver0(inner), puzzle_promise::Message::Message0(message)) => {
                inner.receive(message)?.into()
            }
            (Receiver::Receiver1(inner), puzzle_promise::Message::Message2(message)) => {
                inner.receive(message, rng)?.into()
            }
            _ => bail!(UnexpectedMessage),
        };

        Ok(receiver)
    }

    pub fn transition_on_puzzle_solver_message(
        self,
        message: puzzle_solver::Message,
    ) -> anyhow::Result<Self> {
        let receiver = match (self, message) {
            (Receiver::Receiver2(inner), puzzle_solver::Message::Message4(message)) => {
                inner.receive(message)?.into()
            }
            _ => anyhow::bail!(UnexpectedMessage),
        };

        Ok(receiver)
    }

    pub fn next_puzzle_promise_message(&self) -> anyhow::Result<puzzle_promise::Message> {
        let message = match self {
            Receiver::Receiver1(inner) => inner.next_message().into(),
            Receiver::Receiver2(inner) => inner.next_message().into(),
            _ => anyhow::bail!(NoMessage),
        };

        Ok(message)
    }

    pub fn redeem_transaction(&self) -> anyhow::Result<bitcoin::Transaction> {
        let transaction = match self {
            Receiver::Receiver3(inner) => inner.signed_redeem_transaction.clone(),
            _ => anyhow::bail!(NoTransaction),
        };

        Ok(transaction)
    }
}

#[derive(Debug, Clone)]
pub struct Receiver0 {
    x_r: secp256k1::KeyPair,
    params: Params,
    HE: hsm_cl::PublicKey,
}

#[derive(Debug, Clone)]
pub struct Receiver1 {
    x_r: secp256k1::KeyPair,
    X_t: secp256k1::PublicKey,
    c_alpha: hsm_cl::Ciphertext,
    A: secp256k1::PublicKey,
    transactions: bitcoin::Transactions,
    sig_refund_r: secp256k1::Signature,
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct Receiver3 {
    signed_redeem_transaction: bitcoin::Transaction,
}

impl Receiver0 {
    pub fn new(params: Params, rng: &mut impl Rng, HE: hsm_cl::PublicKey) -> Self {
        Self {
            x_r: secp256k1::KeyPair::random(rng),
            params,
            HE,
        }
    }

    pub fn receive(
        self,
        puzzle_promise::Message0 {
            X_t,
            c_alpha,
            pi_alpha,
            A,
        }: puzzle_promise::Message0,
    ) -> anyhow::Result<Receiver1> {
        let Receiver0 { x_r, params, HE } = self;

        let statement = (&c_alpha, &A);
        hsm_cl::verify(&HE, &pi_alpha, statement)?;

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

        let sig_refund_r = secp256k1::sign(transactions.refund_tx_digest, &x_r);

        Ok(Receiver1 {
            x_r,
            X_t,
            c_alpha,
            A,
            transactions,
            sig_refund_r,
        })
    }
}

impl Receiver1 {
    pub fn next_message(&self) -> puzzle_promise::Message1 {
        puzzle_promise::Message1 {
            X_r: self.x_r.to_pk(),
            sig_refund_r: self.sig_refund_r.clone(),
        }
    }

    pub fn receive(
        self,
        puzzle_promise::Message2 { sig_redeem_t }: puzzle_promise::Message2,
        rng: &mut impl Rng,
    ) -> anyhow::Result<Receiver2> {
        let Self {
            x_r,
            X_t,
            A,
            c_alpha,
            transactions,
            ..
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
    pub fn receive(
        self,
        puzzle_solver::Message4 { alpha_macron }: puzzle_solver::Message4,
    ) -> anyhow::Result<Receiver3> {
        let Self {
            X_t,
            x_r,
            transactions,
            sig_redeem_t,
            sig_redeem_r,
            beta,
            ..
        } = self;

        let alpha = {
            let alpha_macron: secp256k1::Scalar = alpha_macron.into();
            let beta: secp256k1::Scalar = beta.into_sk().into();

            alpha_macron * beta.inv()
        };

        let sig_redeem_t = secp256k1::decsig(&secp256k1::KeyPair::try_from(alpha)?, &sig_redeem_t);

        secp256k1::verify(transactions.redeem_tx_digest, &sig_redeem_t, &X_t)
            .context("failed to verify tumbler redeem signature after decryption")?;

        let signed_redeem_transaction = bitcoin::complete_spend_transaction(
            transactions.redeem,
            (X_t, sig_redeem_t),
            (x_r.to_pk(), sig_redeem_r),
        )?;

        Ok(Receiver3 {
            signed_redeem_transaction,
        })
    }

    pub fn next_message(&self) -> puzzle_promise::Message3 {
        let l = Lock {
            c_alpha_prime: self.c_alpha_prime.clone(),
            A_prime: self.A_prime.clone(),
        };

        puzzle_promise::Message3 { l }
    }
}

impl Receiver3 {
    pub fn signed_redeem_transaction(&self) -> &bitcoin::Transaction {
        &self.signed_redeem_transaction
    }
}
