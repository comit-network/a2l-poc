#![allow(non_snake_case)]

pub mod dummy_hsm_cl;
pub mod puzzle_promise;
pub mod puzzle_solver;
pub mod secp256k1;

pub use bitcoin::secp256k1::rand;

#[derive(Default, Clone)]
pub struct Input;

#[derive(Clone)]
pub struct Params {
    pub redeem_identity: secp256k1::PublicKey,
    pub refund_identity: secp256k1::PublicKey,
    pub expiry: u32,
    pub value: u64,
    pub fund_transaction: bitcoin::Transaction,
}

#[derive(Default)]
pub struct EncryptedSignature;
