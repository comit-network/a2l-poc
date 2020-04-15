use crate::*;

// tumbler to sender
pub struct Message0 {
    tumbler_pk: secp256k1::PublicKey,
}

// sender to tumbler
pub struct Message1 {
    // key generation
    sender_pk: secp256k1::PublicKey,
    // protocol
    c_alpha_prime_prime: dummy_hsm_cl::Ciphertext,
}

// tumbler to sender
pub struct Message2 {
    A_prime_prime: secp256k1::PublicKey,
    refund_sig: secp256k1::Signature,
}

// sender to tumbler
#[derive(Default)]
pub struct Message3 {
    redeem_encsig: EncryptedSignature,
}

// sender to receiver
pub struct Message4 {
    alpha_tilde: secp256k1::SecretKey,
}
