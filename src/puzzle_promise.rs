use crate::dummy_hsm_cl as hsm_cl;
use crate::*;
use std::rc::Rc;

pub struct Tumbler0 {
    x_2: secp256k1::KeyPair,
    hsm_cl: Rc<hsm_cl::System>,
    a: hsm_cl::KeyPair,
    c_alpha: hsm_cl::Ciphertext,
    pi_alpha: hsm_cl::Proof,
}

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
        unimplemented!()
    }

    pub fn receive(self, message: Message2) -> Receiver2 {
        Receiver2
    }
}

impl Tumbler0 {
    pub fn new(params: Params, x_2: secp256k1::KeyPair, hsm_cl: Rc<hsm_cl::System>) -> Self {
        let a = hsm_cl.keygen();
        let (c_alpha, pi_alpha) = hsm_cl.encrypt(&a, &x_2);

        Self {
            x_2,
            hsm_cl,
            a,
            c_alpha,
            pi_alpha,
        }
    }

    pub fn next_message(&self) -> Message0 {
        Message0 {
            tumbler_pk: self.x_2.to_pk(),
            A: self.a.to_pk(),
            pi_alpha: self.pi_alpha.clone(),
            c_alpha: self.c_alpha.clone(),
        }
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

pub struct Message0 {
    // key generation
    tumbler_pk: secp256k1::PublicKey,
    // protocol
    A: hsm_cl::PublicKey,
    pi_alpha: hsm_cl::Proof,
    c_alpha: hsm_cl::Ciphertext,
}

pub struct Message1 {
    // key generation
    receiver_pk: secp256k1::PublicKey,
    // protocol
    refund_sig: secp256k1::Signature,
}

#[derive(Default)]
pub struct Message2 {
    redeem_encsig: EncryptedSignature,
}

// receiver to sender
#[derive(Default)]
pub struct Message3 {
    A_prime: hsm_cl::PublicKey,
    c_alpha_prime: hsm_cl::Ciphertext,
}
