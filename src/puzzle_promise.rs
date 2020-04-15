use crate::dummy_hsm_cl as hsm_cl;
use crate::*;
use std::rc::Rc;

pub struct Tumbler0 {
    x_t: secp256k1::KeyPair,
    hsm_cl: Rc<hsm_cl::System>,
    a: hsm_cl::KeyPair,
    c_alpha: hsm_cl::Ciphertext,
    pi_alpha: hsm_cl::Proof,
}

pub struct Sender0;

pub struct Receiver0 {
    x_r: secp256k1::KeyPair,
    params: Params,
}

pub struct Sender1;

pub struct Tumbler1;

pub struct Receiver1 {
    x_r: secp256k1::KeyPair,
    X_t: secp256k1::PublicKey,
    params: Params,
}

pub struct Receiver2;

impl Receiver0 {
    pub fn new(params: Params, x_r: secp256k1::KeyPair) -> Self {
        Self { x_r, params }
    }

    pub fn receive(self, message: Message0) -> Receiver1 {
        Receiver1 {
            x_r: self.x_r,
            X_t: message.X_t,
            params: self.params,
        }
    }
}

impl Receiver1 {
    pub fn next_message(&self) -> Message1 {
        Message1 {
            X_r: self.x_r.to_pk(),
            // refund_sig: secp256k1::Signature,
        }
    }

    pub fn receive(self, message: Message2) -> Receiver2 {
        Receiver2
    }
}

impl Tumbler0 {
    pub fn new(params: Params, x_t: secp256k1::KeyPair, hsm_cl: Rc<hsm_cl::System>) -> Self {
        let a = hsm_cl.keygen();
        let (c_alpha, pi_alpha) = hsm_cl.encrypt(&a, &x_t);

        Self {
            x_t,
            hsm_cl,
            a,
            c_alpha,
            pi_alpha,
        }
    }

    pub fn next_message(&self) -> Message0 {
        Message0 {
            X_t: self.x_t.to_pk(),
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
        unimplemented!()
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
    X_t: secp256k1::PublicKey,
    // protocol
    A: hsm_cl::PublicKey,
    pi_alpha: hsm_cl::Proof,
    c_alpha: hsm_cl::Ciphertext,
}

pub struct Message1 {
    // key generation
    X_r: secp256k1::PublicKey,
    // protocol
    // refund_sig: secp256k1::Signature,
}

#[derive(Default)]
pub struct Message2 {
    redeem_encsig: EncryptedSignature,
}

// receiver to sender
pub struct Message3 {
    A_prime: hsm_cl::PublicKey,
    c_alpha_prime: hsm_cl::Ciphertext,
}
