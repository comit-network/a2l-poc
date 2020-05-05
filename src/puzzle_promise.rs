use crate::{hsm_cl, secp256k1, Lock};

mod tumbler;

pub use tumbler::{Tumbler, Tumbler0, Tumbler1};

#[derive(Debug, derive_more::From, serde::Serialize)]
pub enum Message {
    Message0(Message0),
    Message1(Message1),
    Message2(Message2),
    Message3(Message3),
}

#[derive(Debug, serde::Serialize)]
pub struct Message0 {
    #[serde(with = "crate::serde::secp256k1_public_key")]
    pub X_t: secp256k1::PublicKey,
    #[serde(with = "crate::serde::secp256k1_public_key")]
    pub A: secp256k1::PublicKey,
    pub c_alpha: hsm_cl::Ciphertext,
    pub pi_alpha: hsm_cl::Proof,
}

#[derive(Debug, serde::Serialize)]
pub struct Message1 {
    #[serde(with = "crate::serde::secp256k1_public_key")]
    pub X_r: secp256k1::PublicKey,
    #[serde(with = "crate::serde::secp256k1_signature")]
    pub sig_refund_r: secp256k1::Signature,
}

#[derive(Debug, serde::Serialize)]
pub struct Message2 {
    pub sig_redeem_t: secp256k1::EncryptedSignature,
}

#[derive(Debug, serde::Serialize)]
pub struct Message3 {
    pub l: Lock,
}
