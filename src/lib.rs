#![allow(non_snake_case)]
#![allow(clippy::large_enum_variant)]

mod dleq;
mod secp256k1;
mod serde;

mod bitcoin;
pub mod hsm_cl;
pub mod puzzle_promise;
pub mod puzzle_solver;
pub mod receiver;
pub mod sender;

pub use self::bitcoin::spend_tx_miner_fee;

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

#[derive(Clone, Debug, ::serde::Serialize)]
pub struct Lock {
    pub c_alpha_prime: hsm_cl::Ciphertext,
    #[serde(with = "crate::serde::secp256k1_public_key")]
    pub A_prime: secp256k1::PublicKey,
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
            + bitcoin::spend_tx_miner_fee(self.spend_transaction_fee_per_wu)
    }

    /// Returns how much the tumbler is supposed to take out of the joint output funded by the sender.
    pub fn sender_tumbler_joint_output_takeout(&self) -> bitcoin::Amount {
        self.tumble_amount + self.tumbler_fee
    }

    /// Returns how much the tumbler has to put into the joint output in the fund transaction.
    pub fn tumbler_receiver_joint_output_value(&self) -> bitcoin::Amount {
        self.tumbler_receiver_joint_output_takeout()
            + bitcoin::spend_tx_miner_fee(self.spend_transaction_fee_per_wu)
    }

    /// Returns how much the receiver is supposed to take out of the joint output funded by the tumbler.
    pub fn tumbler_receiver_joint_output_takeout(&self) -> bitcoin::Amount {
        self.tumble_amount
    }
}
