#![allow(non_snake_case)]

pub mod bitcoin;
mod dleq;
pub mod dummy_hsm_cl;
pub mod puzzle_promise;
pub mod puzzle_solver;
pub mod secp256k1;

#[derive(Default, Clone)]
pub struct Input;

#[derive(Clone)]
pub struct Params {
    pub redeem_identity: bitcoin::Address,
    pub refund_identity: bitcoin::Address,
    pub expiry: u32,
    pub tumble_amount: u64,
    pub tumbler_fee: u64,
    pub spend_transaction_fee_per_wu: u64,
    /// A fully-funded transaction that is only missing the joint output.
    ///
    /// Fully-funded means we expect this transaction to have enough inputs to pay the joint output
    /// of value `amount` and in addition have one or more change outputs that already incorporate
    /// the fee the user is willing to pay.
    pub partial_fund_transaction: bitcoin::Transaction,
    pub fund_transaction_fee: u64,
}

#[derive(Clone, Debug)]
pub struct Lock {
    pub c_alpha_prime: dummy_hsm_cl::Ciphertext,
    pub A_prime: secp256k1::PublicKey,
}
