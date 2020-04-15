#![allow(non_snake_case)]

#[derive(Default, Clone)]
pub struct Input;

#[derive(Default, Clone)]
pub struct Params {
    redeem_identity: PublicKey,
    refund_identity: PublicKey,
    value: u64,
    expiry: u32,
    fund_input: Input,
    fund_change_identity: PublicKey,
}

#[derive(Default)]
pub struct SecretKey;
#[derive(Default, Clone)]
pub struct PublicKey;
#[derive(Default)]
pub struct Signature;
#[derive(Default)]
pub struct EncryptedSignature;

pub mod puzzle_promise {
    use super::*;
    use crate::dummy_hsmcl;

    pub struct Tumbler0;
    pub struct Sender0;
    pub struct Receiver0;

    pub struct Sender1;
    pub struct Tumbler1;
    pub struct Receiver1;

    pub struct Receiver2;

    impl Receiver0 {
        pub fn new(params: Params) -> Self {
            Self
        }

        pub fn receive(self, message: Message0) -> Receiver1 {
            Receiver1
        }
    }

    impl Receiver1 {
        pub fn next_message(&self) -> Message1 {
            Message1::default()
        }

        pub fn receive(self, message: Message2) -> Receiver2 {
            Receiver2
        }
    }

    impl Tumbler0 {
        pub fn new(params: Params) -> Self {
            Self
        }

        pub fn next_message(&self) -> Message0 {
            Message0::default()
        }

        pub fn receive(self, message: Message1) -> Tumbler1 {
            Tumbler1
        }
    }

    impl Tumbler1 {
        pub fn next_message(&self) -> Message2 {
            Message2::default()
        }
    }

    impl Receiver2 {
        pub fn next_message(&self) -> Message3 {
            Message3::default()
        }
    }

    impl Sender0 {
        pub fn new() -> Self {
            Self
        }

        pub fn receive(self, message: Message3) -> Sender1 {
            Sender1
        }
    }

    #[derive(Default)]
    pub struct Message0 {
        // key generation
        tumbler_pk: PublicKey,
        // protocol
        A: PublicKey,
        pi_alpha: dummy_hsmcl::Proof,
        c_alpha: dummy_hsmcl::Ciphertext,
    }

    #[derive(Default)]
    pub struct Message1 {
        // key generation
        receiver_pk: PublicKey,
        // protocol
        refund_sig: Signature,
    }

    #[derive(Default)]
    pub struct Message2 {
        redeem_encsig: EncryptedSignature,
    }

    // receiver to sender
    #[derive(Default)]
    pub struct Message3 {
        A_prime: PublicKey,
        c_alpha_prime: dummy_hsmcl::Ciphertext,
    }
}

pub mod puzzle_solver {
    use super::*;

    // tumbler to sender
    #[derive(Default)]
    pub struct Message0 {
        tumbler_pk: PublicKey,
    }

    // sender to tumbler
    #[derive(Default)]
    pub struct Message1 {
        // key generation
        sender_pk: PublicKey,
        // protocol
        c_alpha_prime_prime: dummy_hsmcl::Ciphertext,
    }

    // tumbler to sender
    #[derive(Default)]
    pub struct Message2 {
        A_prime_prime: PublicKey,
        refund_sig: Signature,
    }

    // sender to tumbler
    #[derive(Default)]
    pub struct Message3 {
        redeem_encsig: EncryptedSignature,
    }

    // sender to receiver
    #[derive(Default)]
    pub struct Message4 {
        alpha_tilde: SecretKey,
    }
}

pub mod dummy_hsmcl {
    #[derive(Default)]
    pub struct PublicKey;
    #[derive(Default)]
    pub struct SecretKey;
    #[derive(Default)]
    pub struct Message;
    #[derive(Default)]
    pub struct Ciphertext;
    #[derive(Default)]
    pub struct Proof;

    pub struct System {}

    #[derive(Default)]
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
