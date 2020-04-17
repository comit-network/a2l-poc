use crate::dummy_hsm_cl as hsm_cl;
use crate::secp256k1;
use crate::Params;
use crate::{bitcoin, ecdsa};
use fehler::throws;
use std::rc::Rc;

pub struct Tumbler0 {
    x_t: secp256k1::KeyPair,
    hsm_cl: Rc<hsm_cl::System<hsm_cl::SecretKey>>,
    a: secp256k1::KeyPair,
    pi_alpha: hsm_cl::Proof,
    l: hsm_cl::Puzzle,
    params: Params,
}

pub struct Sender0;

pub struct Receiver0 {
    x_r: secp256k1::KeyPair,
    params: Params,
    hsm_cl: Rc<hsm_cl::System<hsm_cl::PublicKey>>,
}

pub struct Sender1 {
    l_prime: hsm_cl::Puzzle,
}

pub struct Tumbler1 {
    X_r: secp256k1::PublicKey,
    x_t: secp256k1::KeyPair,
    receiver_refund_sig: secp256k1::Signature,
    joint_output: bitcoin::TxOut,
    joint_outpoint: bitcoin::OutPoint,
    a: secp256k1::KeyPair,
    redeem_amount: u64,
    redeem_identity: secp256k1::PublicKey,
}

pub struct Receiver1 {
    x_r: secp256k1::KeyPair,
    X_t: secp256k1::PublicKey,
    hsm_cl: Rc<hsm_cl::System<hsm_cl::PublicKey>>,
    l: hsm_cl::Puzzle,
    joint_output: bitcoin::TxOut,
    joint_outpoint: bitcoin::OutPoint,
    redeem_identity: secp256k1::PublicKey,
    refund_identity: secp256k1::PublicKey,
    expiry: u32,
    amount: u64,
}

pub struct Receiver2 {
    hsm_cl: Rc<hsm_cl::System<hsm_cl::PublicKey>>,
    beta: secp256k1::KeyPair,
    l_prime: hsm_cl::Puzzle,
}

impl Receiver0 {
    pub fn new<R: rand::Rng>(
        params: Params,
        hsm_cl: Rc<hsm_cl::System<hsm_cl::PublicKey>>,
        rng: &mut R,
    ) -> Self {
        Self {
            x_r: secp256k1::KeyPair::random(rng),
            params,
            hsm_cl,
        }
    }

    #[throws(anyhow::Error)]
    pub fn receive(self, Message0 { X_t, pi_alpha, l }: Message0) -> Receiver1 {
        let Receiver0 {
            x_r,
            params:
                Params {
                    redeem_identity,
                    refund_identity,
                    expiry,
                    partial_fund_transaction: fund_transaction,
                    amount,
                },
            hsm_cl,
        } = self;

        hsm_cl.verify_puzzle(pi_alpha, &l)?;

        // TODO: account for fee in these amounts

        let (joint_output, joint_outpoint) =
            bitcoin::make_joint_output(fund_transaction, amount, &X_t, &x_r.to_pk());

        Receiver1 {
            x_r,
            X_t,
            joint_outpoint,
            joint_output,
            hsm_cl,
            l,
            redeem_identity,
            refund_identity,
            expiry,
            amount,
        }
    }
}

impl Receiver1 {
    pub fn next_message(&self) -> Message1 {
        let signature = bitcoin::make_refund_signature(
            self.joint_outpoint,
            self.joint_output.clone(),
            self.expiry,
            self.amount,
            &self.refund_identity,
            &self.x_r,
        );

        Message1 {
            X_r: self.x_r.to_pk(),
            refund_sig: signature,
        }
    }

    pub fn receive<R: rand::Rng>(self, _message: Message2, rng: &mut R) -> Receiver2 {
        let beta = secp256k1::KeyPair::random(rng);
        let l_prime = self.hsm_cl.randomize_puzzle(&self.l);

        Receiver2 {
            hsm_cl: self.hsm_cl,
            beta,
            l_prime,
        }
    }
}

impl Tumbler0 {
    pub fn new<R: rand::Rng>(
        params: Params,
        hsm_cl: Rc<hsm_cl::System<hsm_cl::SecretKey>>,
        rng: &mut R,
    ) -> Self {
        let x_t = secp256k1::KeyPair::random(rng);
        let a = secp256k1::KeyPair::random(rng);
        let (pi_alpha, l) = hsm_cl.make_puzzle(&x_t);

        Self {
            x_t,
            hsm_cl,
            a,
            l,
            pi_alpha,
            params,
        }
    }

    pub fn next_message(&self) -> Message0 {
        Message0 {
            X_t: self.x_t.to_pk(),
            l: self.l.clone(),
            pi_alpha: self.pi_alpha.clone(),
        }
    }

    pub fn receive(self, message: Message1) -> Tumbler1 {
        let X_r = message.X_r;

        let (joint_output, joint_outpoint) = bitcoin::make_joint_output(
            self.params.partial_fund_transaction,
            self.params.amount,
            &self.x_t.to_pk(),
            &X_r,
        );

        Tumbler1 {
            X_r,
            x_t: self.x_t,
            receiver_refund_sig: message.refund_sig,
            joint_output,
            joint_outpoint,
            a: self.a,
            redeem_amount: self.params.amount, // TODO: Handle fee
            redeem_identity: self.params.redeem_identity,
        }
    }
}

impl Tumbler1 {
    pub fn next_message<R: rand::Rng>(&self, rng: &mut R) -> Message2 {
        let signature = bitcoin::make_redeem_signature(
            rng,
            self.joint_outpoint,
            self.joint_output.clone(),
            self.redeem_amount,
            &self.redeem_identity,
            &self.x_t,
            &self.a.to_pk(),
        );

        Message2 {
            redeem_encsig: signature,
        }
    }
}

impl Receiver2 {
    pub fn next_message(&self) -> Message3 {
        Message3 {
            l_prime: self.l_prime.clone(),
        }
    }
}

impl Sender0 {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self
    }

    pub fn receive(self, message: Message3) -> Sender1 {
        Sender1 {
            l_prime: message.l_prime,
        }
    }
}

pub struct Message0 {
    // key generation
    X_t: secp256k1::PublicKey,
    // protocol
    l: hsm_cl::Puzzle,
    pi_alpha: hsm_cl::Proof,
}

pub struct Message1 {
    // key generation
    X_r: secp256k1::PublicKey,
    // protocol
    refund_sig: secp256k1::Signature,
}

pub struct Message2 {
    redeem_encsig: ecdsa::EncryptedSignature,
}

// receiver to sender
pub struct Message3 {
    l_prime: hsm_cl::Puzzle,
}
