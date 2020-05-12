use crate::{
    bitcoin, hsm_cl, pedersen,
    pointcheval_sanders::{self, randomize, unblind},
    puzzle_promise, puzzle_solver, random_bls12_381_scalar, secp256k1, Lock, NoMessage,
    NoTransaction, Params, Token, UnexpectedMessage, UnexpectedTransaction,
};
use anyhow::Context;
use rand::Rng;
use std::convert::TryInto;

#[derive(Debug, derive_more::From, Clone, strum_macros::Display)]
pub enum Sender {
    Sender0(Sender0),
    Sender1(Sender1),
    Sender2(Sender2),
    Sender3(Sender3),
    Sender4(Sender4),
    Sender5(Sender5),
}

impl Sender {
    pub fn new(params: Params, PS: pointcheval_sanders::PublicKey, rng: &mut impl Rng) -> Self {
        Sender0::new(params, PS, rng).into()
    }

    pub fn transition_on_puzzle_promise_message(
        self,
        message: puzzle_promise::Message,
        rng: &mut impl Rng,
    ) -> anyhow::Result<Self> {
        let sender = match (self, message) {
            (Sender::Sender2(inner), puzzle_promise::Message::Message4(message)) => {
                inner.receive(message, rng).into()
            }
            (state, message) => anyhow::bail!(UnexpectedMessage::new(message, state)),
        };

        Ok(sender)
    }

    pub fn transition_on_puzzle_solver_message(
        self,
        message: puzzle_solver::Message,
        rng: &mut impl Rng,
    ) -> anyhow::Result<Self> {
        let sender = match (self, message) {
            (Sender::Sender0(inner), puzzle_solver::Message::Message1(message)) => {
                inner.receive(message)?.into()
            }
            (Sender::Sender1(inner), puzzle_solver::Message::Message2(message)) => {
                inner.receive(message, rng).into()
            }
            (Sender::Sender3(inner), puzzle_solver::Message::Message5(message)) => {
                inner.receive(message, rng)?.into()
            }
            (state, message) => anyhow::bail!(UnexpectedMessage::new(message, state)),
        };

        Ok(sender)
    }

    pub fn transition_on_transaction(
        self,
        transaction: puzzle_solver::RedeemTransaction,
    ) -> anyhow::Result<Self> {
        let sender = match self {
            Sender::Sender4(inner) => inner.receive(transaction)?.into(),
            _ => anyhow::bail!(UnexpectedTransaction),
        };

        Ok(sender)
    }

    pub fn next_puzzle_solver_message(&self) -> anyhow::Result<puzzle_solver::Message> {
        let message = match self {
            Sender::Sender0(inner) => inner.next_message().into(),
            Sender::Sender2(inner) => inner.next_message().into(),
            Sender::Sender3(inner) => inner.next_message().into(),
            Sender::Sender4(inner) => inner.next_message().into(),
            Sender::Sender5(inner) => inner.next_message().into(),
            state => anyhow::bail!(NoMessage::new(state.clone())),
        };

        Ok(message)
    }

    pub fn unsigned_fund_transaction(&self) -> anyhow::Result<puzzle_solver::FundTransaction> {
        match self {
            Sender::Sender1(inner) => Ok(inner.unsigned_fund_transaction()),
            _ => anyhow::bail!(NoTransaction),
        }
    }

    pub fn signed_refund_transaction(&self) -> anyhow::Result<puzzle_solver::RefundTransaction> {
        let transaction = match self {
            Sender::Sender1(inner) => inner.signed_refund_transaction.clone(),
            Sender::Sender2(inner) => inner.signed_refund_transaction.clone(),
            Sender::Sender3(inner) => inner.signed_refund_transaction.clone(),
            Sender::Sender4(inner) => inner.signed_refund_transaction.clone(),
            _ => anyhow::bail!(NoTransaction),
        };

        Ok(puzzle_solver::RefundTransaction(transaction))
    }
}

#[derive(Debug, Clone)]
pub struct Sender0 {
    params: Params,
    x_s: secp256k1::KeyPair,
    token: Token,
    C: pedersen::Commitment,
    pi_C: pedersen::Proof,
    D: pedersen::Decommitment,
}

#[derive(Debug, Clone)]
pub struct Sender1 {
    signed_refund_transaction: bitcoin::Transaction,
    transactions: bitcoin::Transactions,
    x_s: secp256k1::KeyPair,
    X_t: secp256k1::PublicKey,
    token: Token,
    D: pedersen::Decommitment,
}

#[derive(Debug, Clone)]
pub struct Sender2 {
    signed_refund_transaction: bitcoin::Transaction,
    transactions: bitcoin::Transactions,
    x_s: secp256k1::KeyPair,
    X_t: secp256k1::PublicKey,
    token: Token,
    sig_token_rand: pointcheval_sanders::Signature,
}

#[derive(Debug, Clone)]
pub struct Sender3 {
    x_s: secp256k1::KeyPair,
    c_alpha_prime_prime: hsm_cl::Ciphertext,
    A_prime: secp256k1::PublicKey,
    tau: secp256k1::KeyPair,
    transactions: bitcoin::Transactions,
    signed_refund_transaction: bitcoin::Transaction,
}

#[derive(Debug, Clone)]
pub struct Sender4 {
    sig_redeem_s: secp256k1::EncryptedSignature,
    A_prime_prime: secp256k1::PublicKey,
    x_s: secp256k1::KeyPair,
    tau: secp256k1::KeyPair,
    redeem_tx_digest: bitcoin::SigHash,
    signed_refund_transaction: bitcoin::Transaction,
}

#[derive(Debug, Clone)]
pub struct Sender5 {
    alpha_macron: secp256k1::KeyPair,
}

#[derive(thiserror::Error, Debug)]
#[error("(A')^tau != A''")]
pub struct AptNotEqualApp;

impl Sender0 {
    pub fn new(params: Params, PS: pointcheval_sanders::PublicKey, rng: &mut impl Rng) -> Self {
        let token = random_bls12_381_scalar(rng);

        let G1 = bls12_381::G1Affine::generator();
        let Y1 = &PS.Y1;
        let (C, D) = pedersen::commit(&G1, Y1, &token, rng);
        let pi_C = pedersen::prove(&G1, Y1, &C, &D, rng);

        Self {
            params,
            x_s: secp256k1::KeyPair::random(rng),
            token,
            C,
            pi_C,
            D,
        }
    }

    pub fn next_message(&self) -> puzzle_solver::Message0 {
        puzzle_solver::Message0 {
            X_s: self.x_s.to_pk(),
            C: self.C,
            pi_C: self.pi_C.clone(),
        }
    }

    pub fn receive(
        self,
        puzzle_solver::Message1 { X_t, sig_refund_t }: puzzle_solver::Message1,
    ) -> anyhow::Result<Sender1> {
        let transactions = bitcoin::make_transactions(
            self.params.partial_fund_transaction.clone(),
            self.params.sender_tumbler_joint_output_value(),
            self.params.sender_tumbler_joint_output_takeout(),
            &self.x_s.to_pk(),
            &X_t,
            self.params.expiry,
            &self.params.redeem_identity,
            &self.params.refund_identity,
        );

        let sig_refund_s = {
            secp256k1::verify(transactions.refund_tx_digest, &sig_refund_t, &X_t)
                .context("failed to verify tumbler refund signature")?;

            secp256k1::sign(transactions.refund_tx_digest, &self.x_s)
        };

        let signed_refund_transaction = bitcoin::complete_spend_transaction(
            transactions.refund.clone(),
            (self.x_s.to_pk(), sig_refund_s),
            (X_t.clone(), sig_refund_t),
        )?;

        Ok(Sender1 {
            signed_refund_transaction,
            transactions,
            X_t,
            x_s: self.x_s,
            token: self.token,
            D: self.D,
        })
    }
}

impl Sender1 {
    pub fn receive(
        self,
        puzzle_solver::Message2 { sig_token_blind }: puzzle_solver::Message2,
        rng: &mut impl Rng,
    ) -> Sender2 {
        let sig_token = unblind(sig_token_blind, self.D.r);
        let sig_token_rand = randomize(&sig_token, rng);

        Sender2 {
            x_s: self.x_s,
            X_t: self.X_t,
            transactions: self.transactions,
            sig_token_rand,
            signed_refund_transaction: self.signed_refund_transaction,
            token: self.token,
        }
    }

    pub fn unsigned_fund_transaction(&self) -> puzzle_solver::FundTransaction {
        puzzle_solver::FundTransaction(self.transactions.fund.clone())
    }
}

impl Sender2 {
    pub fn next_message(&self) -> puzzle_solver::Message3 {
        puzzle_solver::Message3 {
            token: self.token,
            sig_token_rand: self.sig_token_rand.clone(),
        }
    }

    pub fn receive(
        self,
        puzzle_promise::Message4 {
            l: Lock {
                c_alpha_prime,
                A_prime,
            },
        }: puzzle_promise::Message4,
        rng: &mut impl Rng,
    ) -> Sender3 {
        let tau = secp256k1::KeyPair::random(rng);
        let c_alpha_prime_prime = &c_alpha_prime * &tau;

        Sender3 {
            x_s: self.x_s,
            A_prime,
            c_alpha_prime_prime,
            tau,
            transactions: self.transactions,
            signed_refund_transaction: self.signed_refund_transaction,
        }
    }
}

impl Sender3 {
    pub fn next_message(&self) -> puzzle_solver::Message4 {
        puzzle_solver::Message4 {
            c_alpha_prime_prime: self.c_alpha_prime_prime.clone(),
        }
    }

    pub fn receive(
        self,
        puzzle_solver::Message5 { A_prime_prime }: puzzle_solver::Message5,
        rng: &mut impl Rng,
    ) -> anyhow::Result<Sender4> {
        let A_prime_tau = {
            let mut A_prime_tau = self.A_prime.clone();
            A_prime_tau.tweak_mul_assign(self.tau.as_sk()).unwrap();
            A_prime_tau
        };
        if A_prime_tau != A_prime_prime {
            anyhow::bail!(AptNotEqualApp)
        }

        let sig_redeem_s = secp256k1::encsign(
            self.transactions.redeem_tx_digest,
            &self.x_s,
            &A_prime_prime,
            rng,
        );

        Ok(Sender4 {
            sig_redeem_s,
            A_prime_prime,
            x_s: self.x_s,
            tau: self.tau,
            redeem_tx_digest: self.transactions.redeem_tx_digest,
            signed_refund_transaction: self.signed_refund_transaction,
        })
    }
}

impl Sender4 {
    pub fn next_message(&self) -> puzzle_solver::Message6 {
        puzzle_solver::Message6 {
            sig_redeem_s: self.sig_redeem_s.clone(),
        }
    }

    pub fn receive(
        self,
        redeem_transaction: puzzle_solver::RedeemTransaction,
    ) -> anyhow::Result<Sender5> {
        let Self {
            sig_redeem_s: encrypted_signature,
            A_prime_prime,
            tau,
            ..
        } = self;

        let decrypted_signature = bitcoin::extract_signature_by_key(
            redeem_transaction.0,
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

        Ok(Sender5 {
            alpha_macron: alpha_macron.try_into()?,
        })
    }

    pub fn signed_refund_transaction(&self) -> bitcoin::Transaction {
        self.signed_refund_transaction.clone()
    }
}

impl Sender5 {
    pub fn next_message(&self) -> puzzle_solver::Message7 {
        puzzle_solver::Message7 {
            alpha_macron: self.alpha_macron.to_sk(),
        }
    }

    pub fn alpha_macron(&self) -> &secp256k1::KeyPair {
        &self.alpha_macron
    }
}
