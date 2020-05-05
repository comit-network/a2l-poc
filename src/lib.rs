#![allow(non_snake_case)]
#![allow(clippy::large_enum_variant)]

use anyhow::Context;
use rand::Rng;

pub mod bitcoin;
mod dleq;
pub mod hsm_cl;
pub mod puzzle_promise;
pub mod puzzle_solver;
pub mod secp256k1;
pub mod serde;

#[derive(Default, Clone)]
pub struct Input;

#[derive(Clone, Debug)]
pub struct Params {
    pub redeem_identity: bitcoin::Address,
    pub refund_identity: bitcoin::Address,
    pub expiry: u32,

    tumble_amount: bitcoin::Amount,
    tumbler_fee: bitcoin::Amount,
    spend_transaction_fee_per_wu: bitcoin::Amount,
    /// A fully-funded transaction that is only missing the joint output.
    ///
    /// Fully-funded means we expect this transaction to have enough inputs to pay the joint output
    /// of value `amount` and in addition have one or more change outputs that already incorporate
    /// the fee the user is willing to pay.
    pub partial_fund_transaction: bitcoin::Transaction,
}

#[derive(thiserror::Error, Debug)]
#[error("received an unexpected message given the current state")]
pub struct UnexpectedMessage;

#[derive(thiserror::Error, Debug)]
#[error("the current state is not meant to produce a message")]
pub struct NoMessage;

#[derive(thiserror::Error, Debug)]
#[error("the current state is not meant to produce a transaction")]
pub struct NoTransaction;

pub trait Transition<M> {
    fn transition(self, message: M, rng: &mut impl Rng) -> anyhow::Result<Self>
    where
        Self: Sized;
}

pub trait NextMessage<M> {
    fn next_message(&self, rng: &mut impl Rng) -> Result<M, NoMessage>;
}

pub trait FundTransaction {
    fn fund_transaction(&self) -> anyhow::Result<bitcoin::Transaction>;
}

pub trait RedeemTransaction {
    fn redeem_transaction(&self) -> anyhow::Result<bitcoin::Transaction>;
}

#[derive(Clone, Debug, ::serde::Serialize)]
pub struct Lock {
    pub c_alpha_prime: hsm_cl::Ciphertext,
    #[serde(with = "crate::serde::secp256k1_public_key")]
    pub A_prime: secp256k1::PublicKey,
}

pub mod a2l_sender {
    use crate::puzzle_solver::Message;
    use crate::{
        bitcoin, hsm_cl, puzzle_promise, puzzle_solver, secp256k1, FundTransaction, Lock,
        NextMessage, NoMessage, NoTransaction, Params, Transition, UnexpectedMessage,
    };
    use anyhow::Context;
    use rand::Rng;
    use std::convert::TryInto;

    #[derive(Debug, derive_more::From)]
    pub enum Sender {
        Sender0(Sender0),
        Sender1(Sender1),
        Sender2(Sender2),
        Sender3(Sender3),
        Sender4(Sender4),
    }

    impl Sender {
        pub fn new(params: Params, rng: &mut impl Rng) -> Self {
            Sender0::new(params, rng).into()
        }
    }

    #[derive(Debug)]
    pub struct Sender0 {
        params: Params,
        x_s: secp256k1::KeyPair,
    }

    #[derive(Debug)]
    pub struct Sender1 {
        params: Params,
        x_s: secp256k1::KeyPair,
        c_alpha_prime: hsm_cl::Ciphertext,
        A_prime: secp256k1::PublicKey,
    }

    #[derive(Debug)]
    pub struct Sender2 {
        params: Params,
        x_s: secp256k1::KeyPair,
        X_t: secp256k1::PublicKey,
        c_alpha_prime: hsm_cl::Ciphertext,
        A_prime: secp256k1::PublicKey,
        tau: secp256k1::KeyPair,
    }

    #[derive(Debug)]
    pub struct Sender3 {
        unsigned_fund_transaction: bitcoin::Transaction,
        signed_refund_transaction: bitcoin::Transaction,
        sig_redeem_s: secp256k1::EncryptedSignature,
        A_prime_prime: secp256k1::PublicKey,
        x_s: secp256k1::KeyPair,
        tau: secp256k1::KeyPair,
        redeem_tx_digest: bitcoin::SigHash,
    }

    #[derive(Debug)]
    pub struct Sender4 {
        alpha_macron: secp256k1::KeyPair,
        signed_refund_transaction: bitcoin::Transaction,
    }

    impl Transition<puzzle_promise::Message> for Sender {
        fn transition(
            self,
            message: puzzle_promise::Message,
            _rng: &mut impl Rng,
        ) -> anyhow::Result<Self>
        where
            Self: Sized,
        {
            let sender = match (self, message) {
                (Sender::Sender0(inner), puzzle_promise::Message::Message3(message)) => {
                    inner.receive(message).into()
                }
                _ => anyhow::bail!(UnexpectedMessage),
            };

            Ok(sender)
        }
    }

    impl Transition<puzzle_solver::Message> for Sender {
        fn transition(
            self,
            message: puzzle_solver::Message,
            rng: &mut impl Rng,
        ) -> anyhow::Result<Self>
        where
            Self: Sized,
        {
            let sender = match (self, message) {
                (Sender::Sender1(inner), puzzle_solver::Message::Message0(message)) => {
                    inner.receive(message, rng).into()
                }
                (Sender::Sender2(inner), puzzle_solver::Message::Message2(message)) => {
                    inner.receive(message, rng)?.into()
                }
                // (Sender::Sender3(inner), In::RedeemTransaction(transaction)) => {
                //     inner.receive(transaction)?.into()
                // }
                _ => anyhow::bail!(UnexpectedMessage),
            };

            Ok(sender)
        }
    }

    impl Transition<bitcoin::Transaction> for Sender {
        fn transition(
            self,
            transaction: bitcoin::Transaction,
            _: &mut impl Rng,
        ) -> anyhow::Result<Self>
        where
            Self: Sized,
        {
            let sender = match self {
                Sender::Sender3(inner) => inner.receive(transaction)?.into(),
                _ => anyhow::bail!(UnexpectedMessage),
            };

            Ok(sender)
        }
    }

    impl FundTransaction for Sender {
        fn fund_transaction(&self) -> anyhow::Result<bitcoin::Transaction> {
            let transaction = match self {
                Sender::Sender3(inner) => inner.unsigned_fund_transaction.clone(),
                _ => anyhow::bail!(NoTransaction),
            };

            Ok(transaction)
        }
    }

    impl NextMessage<puzzle_solver::Message> for Sender {
        fn next_message(&self, _: &mut impl Rng) -> Result<Message, NoMessage> {
            let message = match self {
                Sender::Sender2(inner) => inner.next_message().into(),
                Sender::Sender3(inner) => inner.next_message().into(),
                Sender::Sender4(inner) => inner.next_message().into(),
                _ => return Err(NoMessage),
            };

            Ok(message)
        }
    }

    #[derive(thiserror::Error, Debug)]
    #[error("(A')^tau != A''")]
    pub struct AptNotEqualApp;

    impl Sender0 {
        pub fn new(params: Params, rng: &mut impl Rng) -> Self {
            Self {
                params,
                x_s: secp256k1::KeyPair::random(rng),
            }
        }

        pub fn receive(
            self,
            puzzle_promise::Message3 {
                l:
                    Lock {
                        c_alpha_prime,
                        A_prime,
                    },
            }: puzzle_promise::Message3,
        ) -> Sender1 {
            Sender1 {
                params: self.params,
                x_s: self.x_s,
                c_alpha_prime,
                A_prime,
            }
        }
    }

    impl Sender1 {
        pub fn receive(
            self,
            puzzle_solver::Message0 { X_t }: puzzle_solver::Message0,
            rng: &mut impl Rng,
        ) -> Sender2 {
            Sender2 {
                params: self.params,
                x_s: self.x_s,
                X_t,
                c_alpha_prime: self.c_alpha_prime,
                A_prime: self.A_prime,
                tau: secp256k1::KeyPair::random(rng),
            }
        }
    }

    impl Sender2 {
        pub fn next_message(&self) -> puzzle_solver::Message1 {
            let c_alpha_prime_prime = &self.c_alpha_prime * &self.tau;

            puzzle_solver::Message1 {
                c_alpha_prime_prime,
                X_s: self.x_s.to_pk(),
            }
        }

        pub fn receive(
            self,
            puzzle_solver::Message2 {
                A_prime_prime,
                sig_refund_t,
            }: puzzle_solver::Message2,
            rng: &mut impl Rng,
        ) -> anyhow::Result<Sender3> {
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

            Ok(Sender3 {
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

    impl Sender3 {
        pub fn next_message(&self) -> puzzle_solver::Message3 {
            puzzle_solver::Message3 {
                sig_redeem_s: self.sig_redeem_s.clone(),
            }
        }

        pub fn receive(self, redeem_transaction: bitcoin::Transaction) -> anyhow::Result<Sender4> {
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

            Ok(Sender4 {
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

    impl Sender4 {
        pub fn next_message(&self) -> puzzle_solver::Message4 {
            puzzle_solver::Message4 {
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
}

pub mod a2l_receiver {
    use crate::{
        bitcoin, hsm_cl, puzzle_promise, puzzle_solver, secp256k1, Lock, NextMessage, NoMessage,
        NoTransaction, Params, RedeemTransaction, Transition, UnexpectedMessage,
    };
    use ::bitcoin::hashes::Hash;
    use anyhow::{bail, Context};
    use hsm_cl::Verify;
    use rand::Rng;
    use std::convert::TryFrom;

    #[derive(Debug, derive_more::From)]
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
    }

    impl Transition<puzzle_promise::Message> for Receiver {
        fn transition(
            self,
            message: puzzle_promise::Message,
            rng: &mut impl Rng,
        ) -> anyhow::Result<Self>
        where
            Self: Sized,
        {
            let tumbler = match (self, message) {
                (Receiver::Receiver0(inner), puzzle_promise::Message::Message0(message)) => {
                    inner.receive(message)?.into()
                }
                (Receiver::Receiver1(inner), puzzle_promise::Message::Message2(message)) => {
                    inner.receive(message, rng)?.into()
                }
                _ => bail!(UnexpectedMessage),
            };

            Ok(tumbler)
        }
    }

    impl Transition<puzzle_solver::Message> for Receiver {
        fn transition(
            self,
            message: puzzle_solver::Message,
            _rng: &mut impl Rng,
        ) -> anyhow::Result<Self> {
            let receiver = match (self, message) {
                (Receiver::Receiver2(inner), puzzle_solver::Message::Message4(message)) => {
                    inner.receive(message)?.into()
                }
                _ => anyhow::bail!(UnexpectedMessage),
            };

            Ok(receiver)
        }
    }

    impl NextMessage<puzzle_promise::Message> for Receiver {
        fn next_message(&self, _rng: &mut impl Rng) -> Result<puzzle_promise::Message, NoMessage> {
            let message = match self {
                Receiver::Receiver1(inner) => inner.next_message().into(),
                Receiver::Receiver2(inner) => inner.next_message().into(),
                _ => return Err(NoMessage),
            };

            Ok(message)
        }
    }

    impl RedeemTransaction for Receiver {
        fn redeem_transaction(&self) -> anyhow::Result<bitcoin::Transaction> {
            let transaction = match self {
                Receiver::Receiver3(inner) => inner.signed_redeem_transaction.clone(),
                _ => anyhow::bail!(NoTransaction),
            };

            Ok(transaction)
        }
    }

    #[derive(Debug)]
    pub struct Receiver0 {
        x_r: secp256k1::KeyPair,
        params: Params,
        HE: hsm_cl::PublicKey,
    }

    #[derive(Debug)]
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

    #[derive(Debug)]
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
        pub fn next_message(&self) -> puzzle_promise::Message1 {
            let sig_refund_r = secp256k1::sign(self.transactions.refund_tx_digest, &self.x_r);

            puzzle_promise::Message1 {
                X_r: self.x_r.to_pk(),
                sig_refund_r,
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

            let sig_redeem_t =
                secp256k1::decsig(&secp256k1::KeyPair::try_from(alpha)?, &sig_redeem_t);

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
}

pub fn local_a2l<TP, TS, S, R, B>(
    tumbler_promise: TP,
    tumbler_solver: TS,
    sender: S,
    receiver: R,
    blockchain: B,
    rng: &mut impl Rng,
) -> anyhow::Result<(TP, TS, S, R, B)>
where
    TP: Transition<puzzle_promise::Message>
        + NextMessage<puzzle_promise::Message>
        + FundTransaction,
    TS: Transition<puzzle_solver::Message>
        + NextMessage<puzzle_solver::Message>
        + RedeemTransaction,
    S: Transition<puzzle_promise::Message>
        + Transition<puzzle_solver::Message>
        + NextMessage<puzzle_solver::Message>
        + FundTransaction
        + Transition<bitcoin::Transaction>,
    R: Transition<puzzle_promise::Message>
        + NextMessage<puzzle_promise::Message>
        + Transition<puzzle_solver::Message>
        + RedeemTransaction,
    B: Transition<bitcoin::Transaction>,
{
    let message = tumbler_promise.next_message(rng)?;
    let receiver = receiver.transition(message, rng)?;
    let message = receiver.next_message(rng)?;
    let tumbler_promise = tumbler_promise.transition(message, rng)?;
    let message = tumbler_promise.next_message(rng)?;
    let receiver = receiver.transition(message, rng)?;
    let message = receiver.next_message(rng)?;
    let sender = sender.transition(message, rng)?;

    let fund_transaction = tumbler_promise.fund_transaction()?;
    let blockchain = blockchain
        .transition(fund_transaction, rng)
        .context("failed to broadcast tumbler's fund transaction")?;

    let message = tumbler_solver.next_message(rng)?;
    let sender = sender.transition(message, rng)?;
    let message = sender.next_message(rng)?;
    let tumbler_solver = tumbler_solver.transition(message, rng)?;
    let message = tumbler_solver.next_message(rng)?;
    let sender = sender.transition(message, rng)?;
    let message = sender.next_message(rng)?;
    let tumbler_solver = tumbler_solver.transition(message, rng)?;

    let fund_transaction = sender.fund_transaction()?;
    let blockchain = blockchain
        .transition(fund_transaction, rng)
        .context("failed to broadcast sender's fund transaction")?;

    let redeem_transaction = tumbler_solver.redeem_transaction()?;
    let blockchain = blockchain
        .transition(redeem_transaction.clone(), rng)
        .context("failed to broadcast tumbler's redeem transaction")?;

    let sender = sender.transition(redeem_transaction, rng)?;
    let message = NextMessage::<puzzle_solver::Message>::next_message(&sender, rng)?;
    let receiver = receiver.transition(message, rng)?;

    let redeem_transaction = receiver.redeem_transaction()?;
    let blockchain = blockchain
        .transition(redeem_transaction, rng)
        .context("failed to broadcast receiver's redeem transaction")?;

    Ok((
        tumbler_promise,
        tumbler_solver,
        sender,
        receiver,
        blockchain,
    ))
}

// TODO: It would make more sense to split this up into something like PromiseParams and SolverParams
impl Params {
    pub fn new(
        redeem_identity: bitcoin::Address,
        refund_identity: bitcoin::Address,
        expiry: u32,
        tumble_amount: bitcoin::Amount,
        tumbler_fee: bitcoin::Amount,
        spend_transaction_fee_per_wu: bitcoin::Amount,
        partial_fund_transaction: bitcoin::Transaction,
    ) -> Self {
        Self {
            redeem_identity,
            refund_identity,
            expiry,
            tumble_amount,
            tumbler_fee,
            spend_transaction_fee_per_wu,
            partial_fund_transaction,
        }
    }

    /// Returns how much the sender has to put into the joint output in the fund transaction.
    pub fn sender_tumbler_joint_output_value(&self) -> bitcoin::Amount {
        self.sender_tumbler_joint_output_takeout()
            + self.spend_transaction_fee_per_wu * bitcoin::MAX_SATISFACTION_WEIGHT
    }

    /// Returns how much the tumbler is supposed to take out of the joint output funded by the sender.
    pub fn sender_tumbler_joint_output_takeout(&self) -> bitcoin::Amount {
        self.tumble_amount + self.tumbler_fee
    }

    /// Returns how much the tumbler has to put into the joint output in the fund transaction.
    pub fn tumbler_receiver_joint_output_value(&self) -> bitcoin::Amount {
        self.tumbler_receiver_joint_output_takeout()
            + self.spend_transaction_fee_per_wu * bitcoin::MAX_SATISFACTION_WEIGHT
    }

    /// Returns how much the receiver is supposed to take out of the joint output funded by the tumbler.
    pub fn tumbler_receiver_joint_output_takeout(&self) -> bitcoin::Amount {
        self.tumble_amount
    }
}
