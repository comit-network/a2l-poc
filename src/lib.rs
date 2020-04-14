#![allow(non_snake_case)]

pub struct Input;

pub struct Params {
    redeem_identity: PublicKey,
    refund_identity: PublicKey,
    value: u64,
    expiry: u32,
    fund_input: Input,
    fund_change_identity: PublicKey,
}

pub struct SecretKey;
pub struct PublicKey;
pub struct Signature;
pub struct EncryptedSignature;

mod puzzle_promise {
    use super::*;
    use crate::dummy_hsmcl;

    // tumbler to receiver
    pub struct Message1 {
        // key generation
        tumbler_pk: PublicKey,
        // protocol
        A: PublicKey,
        pi_alpha: dummy_hsmcl::Proof,
        c_alpha: dummy_hsmcl::Ciphertext,
    }

    // receiver to tumbler
    pub struct Message2 {
        // key generation
        receiver_pk: PublicKey,
        // protocol
        refund_sig: Signature,
    }

    // tumbler to receiver
    pub struct Message3 {
        redeem_encsig: EncryptedSignature,
    }

    // receiver to sender
    pub struct Message4 {
        A_prime: PublicKey,
        c_alpha_prime: dummy_hsmcl::Ciphertext,
    }
}

mod puzzle_solver {
    use super::*;

    // tumbler to sender
    pub struct Message1 {
        tumbler_pk: PublicKey,
    }

    // sender to tumbler
    pub struct Message2 {
        // key generation
        sender_pk: PublicKey,
        // protocol
        c_alpha_prime_prime: dummy_hsmcl::Ciphertext,
    }

    // tumbler to sender
    pub struct Message3 {
        A_prime_prime: PublicKey,
        refund_sig: Signature,
    }

    // sender to tumbler
    pub struct Message4 {
        redeem_encsig: EncryptedSignature,
    }

    // sender to receiver
    pub struct Message5 {
        alpha_tilde: SecretKey,
    }
}

mod dummy_hsmcl {
    pub struct PublicKey;
    pub struct SecretKey;
    pub struct Message;
    pub struct Ciphertext;
    pub struct Proof;

    pub struct System {}

    pub struct KeyPair {
        sk: SecretKey,
        pk: PublicKey,
    }

    pub struct VerificationError;

    impl System {
        pub fn new() -> Self {
            unimplemented!()
        }

        pub fn keygen(&self) -> KeyPair {
            unimplemented!()
        }

        pub fn encrypt(
            &self,
            _keypair: &KeyPair,
            _message: &super::SecretKey,
        ) -> (Ciphertext, Proof) {
            unimplemented!()
        }

        pub fn verify(
            &self,
            _pk: PublicKey,
            _ciphertext: Ciphertext,
            _proof: Proof,
        ) -> Result<(), VerificationError> {
            unimplemented!()
        }

        pub fn decrypt(&self, _keypair: &KeyPair, _ciphertext: Ciphertext) -> super::SecretKey // Result<super::SecretKey, DecryptionError>
        {
            unimplemented!()
        }

        pub fn multiply(&self, _ciphertext: Ciphertext, _sk: &super::SecretKey) -> Ciphertext {
            unimplemented!()
        }
    }
}
