#![allow(non_snake_case)]
#![allow(clippy::large_enum_variant)]

mod bitcoin;
mod dleq;
mod pedersen;

pub mod hsm_cl;
pub mod pointcheval_sanders;
pub mod puzzle_promise;
pub mod puzzle_solver;
pub mod receiver;
pub mod secp256k1;
pub mod sender;
mod serde;

pub use self::bitcoin::spend_tx_miner_fee;
use rand::Rng;
use std::fmt;

#[derive(thiserror::Error, Debug)]
#[error("received an unexpected message {message} given the current state {state}")]
pub struct UnexpectedMessage<M: fmt::Display + fmt::Debug, S: fmt::Display + fmt::Debug> {
    message: M,
    state: S,
}

impl<M: fmt::Display + fmt::Debug, S: fmt::Display + fmt::Debug> UnexpectedMessage<M, S> {
    pub fn new(message: M, state: S) -> Self {
        Self { message, state }
    }
}

#[derive(thiserror::Error, Debug)]
#[error("received an unexpected message given the current state")]
pub struct UnexpectedTransaction;

#[derive(thiserror::Error, Debug)]
#[error("state {state} is not meant to produce a message")]
pub struct NoMessage<S: fmt::Display + fmt::Debug> {
    state: S,
}

impl<S: fmt::Display + fmt::Debug> NoMessage<S> {
    pub fn new(state: S) -> Self {
        Self { state }
    }
}

#[derive(thiserror::Error, Debug)]
#[error("the current state is not meant to produce a transaction")]
pub struct NoTransaction;

#[derive(Clone, Debug, ::serde::Serialize)]
pub struct Lock {
    pub c_alpha_prime: hsm_cl::Ciphertext,
    #[serde(with = "crate::serde::secp256k1_public_key")]
    pub A_prime: secp256k1::PublicKey,
}

pub type Token = bls12_381::Scalar;

fn random_bls12_381_scalar(rng: &mut impl Rng) -> bls12_381::Scalar {
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes[..]);
    bls12_381::Scalar::from_bytes_wide(&bytes)
}
