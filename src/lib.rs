#![allow(non_snake_case)]

pub mod bitcoin;
pub mod dleq;
pub mod dummy_hsm_cl;
pub mod ecdsa;
pub mod puzzle_promise;
pub mod puzzle_solver;
pub mod secp256k1;

#[derive(Default, Clone)]
pub struct Input;

#[derive(Clone)]
pub struct Params {
    pub redeem_identity: secp256k1::PublicKey,
    pub refund_identity: secp256k1::PublicKey,
    pub expiry: u32,
    pub amount: u64,
    /// A fully-funded transaction that is only missing the joint output.
    ///
    /// Fully-funded means we expect this transaction to have enough inputs to pay the joint output
    /// of value `amount` and in addition have one or more change outputs that already incorporate
    /// the fee the user is willing to pay.
    pub partial_fund_transaction: bitcoin::Transaction,
}
