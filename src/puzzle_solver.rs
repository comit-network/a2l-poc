use crate::dummy_hsm_cl as hsm_cl;
use crate::dummy_hsm_cl::Multiply as _;
use crate::secp256k1;
use crate::Lock;
use crate::Params;

pub struct Tumbler0 {
    x_t: secp256k1::KeyPair,
    hsm_cl: hsm_cl::SecretKey,
    params: Params,
}

impl Tumbler0 {
    pub fn new(params: Params, x_t: secp256k1::KeyPair, hsm_cl: hsm_cl::SecretKey) -> Self {
        Self {
            x_t,
            params,
            hsm_cl,
        }
    }

    pub fn next_message(&self) -> Message0 {
        Message0 {
            X_t: self.x_t.to_pk(),
        }
    }
}

pub struct Sender0 {
    params: Params,
    x_s: secp256k1::KeyPair,
    c_alpha_prime: hsm_cl::Ciphertext,
    A_prime: secp256k1::PublicKey,
    hsm_cl: hsm_cl::PublicKey,
}

impl Sender0 {
    pub fn new<R: rand::Rng>(
        params: Params,
        Lock {
            c_alpha_prime,
            A_prime,
        }: Lock,
        hsm_cl: hsm_cl::PublicKey,
        rng: &mut R,
    ) -> Self {
        Self {
            params,
            x_s: secp256k1::KeyPair::random(rng),
            hsm_cl,
            c_alpha_prime,
            A_prime,
        }
    }

    pub fn receive(self, Message0 { X_t }: Message0, rng: &mut impl rand::Rng) -> Sender1 {
        Sender1 {
            params: self.params,
            x_s: self.x_s,
            X_t,
            c_alpha_prime: self.c_alpha_prime,
            A_prime: self.A_prime,
            tau: secp256k1::KeyPair::random(rng),
            hsm_cl: self.hsm_cl,
        }
    }
}

pub struct Sender1 {
    params: Params,
    x_s: secp256k1::KeyPair,
    X_t: secp256k1::PublicKey,
    c_alpha_prime: hsm_cl::Ciphertext,
    A_prime: secp256k1::PublicKey,
    tau: secp256k1::KeyPair,
    hsm_cl: hsm_cl::PublicKey,
}

impl Sender1 {
    pub fn next_message(&self) -> Message1 {
        let c_alpha_prime_prime = self.hsm_cl.multiply(&self.c_alpha_prime, &self.tau);

        Message1 {
            c_alpha_prime_prime,
            X_s: self.x_s.to_pk(),
        }
    }
}

pub struct Tumbler1 {
    params: Params,
    x_t: secp256k1::KeyPair,
    A_prime_prime: secp256k1::PublicKey,
}

// tumbler to sender
pub struct Message0 {
    X_t: secp256k1::PublicKey,
}

// sender to tumbler
pub struct Message1 {
    // key generation
    X_s: secp256k1::PublicKey,
    // protocol
    c_alpha_prime_prime: hsm_cl::Ciphertext,
}

// tumbler to sender
pub struct Message2 {
    A_prime_prime: secp256k1::PublicKey,
    refund_sig: secp256k1::Signature,
}

// sender to tumbler
pub struct Message3 {
    redeem_encsig: secp256k1::EncryptedSignature,
}

// sender to receiver
pub struct Message4 {
    alpha_tilde: secp256k1::SecretKey,
}
