#![allow(non_snake_case)]
#![allow(clippy::large_enum_variant)]

use anyhow::Context;
use rand::Rng;

pub mod bitcoin;
mod dleq;
pub mod hsm_cl;
pub mod puzzle_promise;
pub mod puzzle_solver;
pub mod receiver;
pub mod secp256k1;
pub mod sender;
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

pub trait Transition<M>: Sized {
    fn transition(self, message: M, rng: &mut impl Rng) -> anyhow::Result<Self>;
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
