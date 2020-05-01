use crate::secp256k1;
use crate::UnexpectedMessage;
use crate::{hsm_cl, Params};

mod receiver;
mod sender;
mod tumbler;

pub use receiver::{Receiver0, Receiver1};
pub use sender::{Sender0, Sender1, Sender2, Sender3};
pub use tumbler::{Tumbler0, Tumbler1, Tumbler2};

#[derive(Debug, serde::Serialize)]
pub struct Message0 {
    #[serde(with = "crate::serde::secp256k1_public_key")]
    X_t: secp256k1::PublicKey,
}

#[derive(Debug, serde::Serialize)]
pub struct Message1 {
    #[serde(with = "crate::serde::secp256k1_public_key")]
    X_s: secp256k1::PublicKey,
    c_alpha_prime_prime: hsm_cl::Ciphertext,
}

#[derive(Debug, serde::Serialize)]
pub struct Message2 {
    #[serde(with = "crate::serde::secp256k1_public_key")]
    A_prime_prime: secp256k1::PublicKey,
    #[serde(with = "crate::serde::secp256k1_signature")]
    sig_refund_t: secp256k1::Signature,
}

#[derive(Debug, serde::Serialize)]
pub struct Message3 {
    sig_redeem_s: secp256k1::EncryptedSignature,
}

#[derive(Debug, serde::Serialize)]
pub struct Message4 {
    #[serde(with = "crate::serde::secp256k1_secret_key")]
    alpha_macron: secp256k1::SecretKey,
}
