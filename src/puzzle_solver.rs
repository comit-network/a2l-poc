use crate::dummy_hsm_cl as hsm_cl;
use crate::secp256k1;

mod receiver;
mod sender;
mod tumbler;

pub use receiver::{Receiver0, Receiver1};
pub use sender::{Sender0, Sender1, Sender2, Sender3};
pub use tumbler::{Tumbler0, Tumbler1, Tumbler2};

pub struct Message0 {
    X_t: secp256k1::PublicKey,
}

pub struct Message1 {
    X_s: secp256k1::PublicKey,
    c_alpha_prime_prime: hsm_cl::Ciphertext,
}

pub struct Message2 {
    A_prime_prime: secp256k1::PublicKey,
    sig_refund_t: secp256k1::Signature,
}

pub struct Message3 {
    sig_redeem_s: secp256k1::EncryptedSignature,
}

pub struct Message4 {
    alpha_macron: secp256k1::SecretKey,
}
