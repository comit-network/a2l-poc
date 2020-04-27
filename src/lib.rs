#![allow(non_snake_case)]

pub mod bitcoin;
mod dleq;
pub mod dummy_hsm_cl;
pub mod hsm_cl;
pub mod puzzle_promise;
pub mod puzzle_solver;
pub mod secp256k1;

#[derive(Default, Clone)]
pub struct Input;

#[derive(Clone, Debug)]
pub struct Params {
    pub redeem_identity: bitcoin::Address,
    pub refund_identity: bitcoin::Address,
    pub expiry: u32,

    tumble_amount: u64,
    tumbler_fee: u64,
    spend_transaction_fee_per_wu: u64,
    /// A fully-funded transaction that is only missing the joint output.
    ///
    /// Fully-funded means we expect this transaction to have enough inputs to pay the joint output
    /// of value `amount` and in addition have one or more change outputs that already incorporate
    /// the fee the user is willing to pay.
    pub partial_fund_transaction: bitcoin::Transaction,
}

impl Params {
    pub fn new(
        redeem_identity: bitcoin::Address,
        refund_identity: bitcoin::Address,
        expiry: u32,
        tumble_amount: u64,
        tumbler_fee: u64,
        spend_transaction_fee_per_wu: u64,
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
    pub fn sender_tumbler_joint_output_value(&self) -> u64 {
        self.sender_tumbler_joint_output_takeout()
            + bitcoin::MAX_SATISFACTION_WEIGHT * self.spend_transaction_fee_per_wu
    }

    /// Returns how much the tumbler is supposed to take out of the joint output funded by the sender.
    pub fn sender_tumbler_joint_output_takeout(&self) -> u64 {
        self.tumble_amount + self.tumbler_fee
    }

    /// Returns how much the tumbler has to put into the joint output in the fund transaction.
    pub fn tumbler_receiver_joint_output_value(&self) -> u64 {
        self.tumbler_receiver_joint_output_takeout()
            + bitcoin::MAX_SATISFACTION_WEIGHT * self.spend_transaction_fee_per_wu
    }

    /// Returns how much the receiver is supposed to take out of the joint output funded by the tumbler.
    pub fn tumbler_receiver_joint_output_takeout(&self) -> u64 {
        self.tumble_amount
    }
}

#[derive(Clone, Debug)]
pub struct Lock {
    pub c_alpha_prime: dummy_hsm_cl::Ciphertext,
    pub A_prime: secp256k1::PublicKey,
}
