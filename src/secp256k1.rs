mod constants;
mod enc;
mod keypair;

pub use self::constants::G;
pub use self::enc::{
    decsig, encsign, encverify, recover, EncryptedSignature, InvalidEncryptedSignature,
};
pub use self::keypair::{KeyPair, XCoor};
pub use secp256k1::{curve::Affine, curve::Scalar, PublicKey, SecretKey, Signature};

use secp256k1::Message;

pub trait ToMessage {
    fn to_message(&self) -> [u8; 32];
}

#[derive(thiserror::Error, Debug)]
#[error("invalid signature")]
pub struct InvalidSignature;

pub fn sign<M: ToMessage, S: AsRef<SecretKey>>(message: M, x: &S) -> Signature {
    let message = Message::parse(&message.to_message());
    let (signature, _) = ::secp256k1::sign(&message, x.as_ref());
    signature
}

pub fn verify<M: ToMessage>(
    message: M,
    signature: &Signature,
    x: &PublicKey,
) -> Result<(), InvalidSignature> {
    let message = Message::parse(&message.to_message());
    let is_valid = ::secp256k1::verify(&message, signature, x);

    if is_valid {
        Ok(())
    } else {
        Err(InvalidSignature)
    }
}
