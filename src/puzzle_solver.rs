pub mod tumbler;

use crate::hsm_cl;
use crate::secp256k1;
pub use tumbler::{Tumbler, Tumbler0, Tumbler1, Tumbler2};

#[derive(Debug, derive_more::From, serde::Serialize)]
pub enum Message {
    Message0(Message0),
    Message1(Message1),
    Message2(Message2),
    Message3(Message3),
    Message4(Message4),
}

#[derive(Debug, serde::Serialize)]
pub struct Message0 {
    #[serde(with = "crate::serde::secp256k1_public_key")]
    pub X_t: secp256k1::PublicKey,
}

#[derive(Debug, serde::Serialize)]
pub struct Message1 {
    #[serde(with = "crate::serde::secp256k1_public_key")]
    pub X_s: secp256k1::PublicKey,
    pub c_alpha_prime_prime: hsm_cl::Ciphertext,
}

#[derive(Debug, serde::Serialize)]
pub struct Message2 {
    #[serde(with = "crate::serde::secp256k1_public_key")]
    pub A_prime_prime: secp256k1::PublicKey,
    #[serde(with = "crate::serde::secp256k1_signature")]
    pub sig_refund_t: secp256k1::Signature,
}

#[derive(Debug, serde::Serialize)]
pub struct Message3 {
    pub sig_redeem_s: secp256k1::EncryptedSignature,
}

#[derive(Debug, serde::Serialize)]
pub struct Message4 {
    #[serde(with = "crate::serde::secp256k1_secret_key")]
    pub alpha_macron: secp256k1::SecretKey,
}
