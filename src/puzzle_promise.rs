use crate::bitcoin;
use crate::Params;
use crate::{
    dummy_hsm_cl as hsm_cl, dummy_hsm_cl::Encrypt as _, dummy_hsm_cl::Multiply as _, secp256k1,
    Lock,
};
use ::bitcoin::hashes::Hash;
use anyhow::Context;
use fehler::throws;

pub struct Tumbler0 {
    x_t: secp256k1::KeyPair,
    a: secp256k1::KeyPair,
    params: Params,
    hsm_cl: hsm_cl::SecretKey,
}

pub struct Sender0;

pub struct Receiver0 {
    x_r: secp256k1::KeyPair,
    params: Params,
    hsm_cl: hsm_cl::PublicKey,
}

#[derive(Debug)]
pub struct Sender1 {
    l: Lock,
}

#[derive(Debug)]
pub struct Tumbler1 {
    x_t: secp256k1::KeyPair,
    a: secp256k1::KeyPair,
    unsigned_fund_transaction: bitcoin::Transaction,
    signed_refund_transaction: bitcoin::Transaction,
    redeem_amount: u64,
    redeem_identity: secp256k1::PublicKey,
}

pub struct Receiver1 {
    x_r: secp256k1::KeyPair,
    X_t: secp256k1::PublicKey,
    hsm_cl: hsm_cl::PublicKey,
    c_alpha: hsm_cl::Ciphertext,
    A: secp256k1::PublicKey,
    fund_transaction: bitcoin::Transaction,
    redeem_identity: secp256k1::PublicKey,
    refund_identity: secp256k1::PublicKey,
    expiry: u32,
    amount: u64,
}

#[derive(Debug)]
pub struct Receiver2 {
    x_r: secp256k1::KeyPair,
    X_t: secp256k1::PublicKey,
    beta: secp256k1::KeyPair,
    c_alpha_prime: hsm_cl::Ciphertext,
    A_prime: secp256k1::PublicKey,
    unsigned_redeem_transaction: bitcoin::Transaction,
    sig_redeem_r: secp256k1::Signature,
    sig_redeem_t: secp256k1::EncryptedSignature,
}

impl Receiver0 {
    pub fn new<R: rand::Rng>(params: Params, hsm_cl: hsm_cl::PublicKey, rng: &mut R) -> Self {
        Self {
            x_r: secp256k1::KeyPair::random(rng),
            params,
            hsm_cl,
        }
    }

    #[throws(anyhow::Error)]
    pub fn receive(self, Message0 { X_t, c_alpha, A }: Message0) -> Receiver1 {
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

        // TODO: Verify c_alpha with pi_alpha (line 8, Figure 6)

        // TODO: account for fee in these amounts

        let fund_transaction =
            bitcoin::make_fund_transaction(fund_transaction, amount, &X_t, &x_r.to_pk());

        Receiver1 {
            x_r,
            X_t,
            fund_transaction,
            hsm_cl,
            c_alpha,
            A,
            redeem_identity,
            refund_identity,
            expiry,
            amount,
        }
    }
}

impl Receiver1 {
    pub fn next_message(&self) -> Message1 {
        let (_, digest) = bitcoin::make_spend_transaction(
            &self.fund_transaction,
            self.amount,
            &self.refund_identity,
            self.expiry,
        );
        let sig_refund_r = secp256k1::sign(digest, &self.x_r);

        Message1 {
            X_r: self.x_r.to_pk(),
            sig_refund_r,
        }
    }

    #[throws(anyhow::Error)]
    pub fn receive<R: rand::Rng>(
        self,
        Message2 { sig_redeem_t }: Message2,
        rng: &mut R,
    ) -> Receiver2 {
        let Self {
            x_r,
            X_t,
            A,
            hsm_cl,
            amount,
            redeem_identity,
            fund_transaction,
            c_alpha,
            ..
        } = self;

        let (unsigned_redeem_transaction, digest) =
            bitcoin::make_spend_transaction(&fund_transaction, amount, &redeem_identity, 0);

        secp256k1::encverify(&X_t, &A, &digest.into_inner(), &sig_redeem_t)?;

        let sig_redeem_r = secp256k1::sign(digest, &x_r);

        let beta = secp256k1::KeyPair::random(rng);
        let c_alpha_prime = hsm_cl.multiply(&c_alpha, &beta);
        let A_prime = hsm_cl.multiply(&A, &beta);

        Receiver2 {
            x_r,
            X_t,
            beta,
            c_alpha_prime,
            A_prime,
            sig_redeem_r,
            sig_redeem_t,
            unsigned_redeem_transaction,
        }
    }
}

impl Tumbler0 {
    pub fn new<R: rand::Rng>(params: Params, hsm_cl: hsm_cl::SecretKey, rng: &mut R) -> Self {
        let x_t = secp256k1::KeyPair::random(rng);
        let a = secp256k1::KeyPair::random(rng);

        Self {
            x_t,
            a,
            params,
            hsm_cl,
        }
    }

    pub fn next_message(&self) -> Message0 {
        let X_t = self.x_t.to_pk();
        let A = self.a.to_pk();
        let c_alpha = self.hsm_cl.encrypt(&self.x_t, self.a.as_ref());

        // TODO: Compute pi_alpha (line 4, Figure 6)

        Message0 { X_t, A, c_alpha }
    }

    #[throws(anyhow::Error)]
    pub fn receive(self, Message1 { X_r, sig_refund_r }: Message1) -> Tumbler1 {
        let unsigned_fund_transaction = bitcoin::make_fund_transaction(
            self.params.partial_fund_transaction,
            self.params.amount,
            &self.x_t.to_pk(),
            &X_r,
        );

        let signed_refund_transaction = {
            let (transaction, digest) = bitcoin::make_spend_transaction(
                &unsigned_fund_transaction,
                self.params.amount,
                &self.params.refund_identity,
                self.params.expiry,
            );

            secp256k1::verify(digest, &sig_refund_r, &X_r)
                .context("failed to verify receiver refund signature")?;

            let sig_refund_t = secp256k1::sign(digest, &self.x_t);

            bitcoin::complete_spend_transaction(
                transaction,
                (self.x_t.to_pk(), sig_refund_t),
                (X_r, sig_refund_r),
            )?
        };

        Tumbler1 {
            x_t: self.x_t,
            unsigned_fund_transaction,
            signed_refund_transaction,
            a: self.a,
            redeem_amount: self.params.amount, // TODO: Handle fee
            redeem_identity: self.params.redeem_identity,
        }
    }
}

impl Tumbler1 {
    pub fn next_message<R: rand::Rng>(&self, rng: &mut R) -> Message2 {
        let (_, digest) = bitcoin::make_spend_transaction(
            &self.unsigned_fund_transaction,
            self.redeem_amount,
            &self.redeem_identity,
            0,
        );
        let sig_redeem_t = secp256k1::encsign(digest, &self.x_t, &self.a.to_pk(), rng);

        Message2 { sig_redeem_t }
    }

    pub fn unsigned_fund_transaction(&self) -> &bitcoin::Transaction {
        &self.unsigned_fund_transaction
    }
    pub fn signed_refund_transaction(&self) -> &bitcoin::Transaction {
        &self.signed_refund_transaction
    }
    pub fn x_t(&self) -> &secp256k1::KeyPair {
        &self.x_t
    }
}

#[derive(Debug)]
pub struct ReceiverOutput {
    unsigned_redeem_transaction: bitcoin::Transaction,
    sig_redeem_t: secp256k1::EncryptedSignature,
    sig_redeem_r: secp256k1::Signature,
    beta: secp256k1::KeyPair,
}

#[derive(Debug)]
pub struct SenderOutput {
    l: Lock,
}

impl Receiver2 {
    pub fn next_message(&self) -> Message3 {
        let l = Lock {
            c_alpha_prime: self.c_alpha_prime.clone(),
            A_prime: self.A_prime.clone(),
        };

        Message3 { l }
    }

    pub fn x_r(&self) -> &secp256k1::KeyPair {
        &self.x_r
    }
    pub fn X_t(&self) -> &secp256k1::PublicKey {
        &self.X_t
    }
    pub fn unsigned_redeem_transaction(&self) -> &bitcoin::Transaction {
        &self.unsigned_redeem_transaction
    }
    pub fn sig_redeem_t(&self) -> &secp256k1::EncryptedSignature {
        &self.sig_redeem_t
    }
    pub fn sig_redeem_r(&self) -> &secp256k1::Signature {
        &self.sig_redeem_r
    }
    pub fn beta(&self) -> &secp256k1::KeyPair {
        &self.beta
    }
}

impl Sender0 {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self
    }

    pub fn receive(self, message: Message3) -> Sender1 {
        Sender1 { l: message.l }
    }
}

impl Sender1 {
    pub fn l(&self) -> &Lock {
        &self.l
    }
}

pub struct Message0 {
    X_t: secp256k1::PublicKey,
    A: secp256k1::PublicKey,
    c_alpha: hsm_cl::Ciphertext,
}

pub struct Message1 {
    X_r: secp256k1::PublicKey,
    sig_refund_r: secp256k1::Signature,
}

pub struct Message2 {
    sig_redeem_t: secp256k1::EncryptedSignature,
}

pub struct Message3 {
    l: Lock,
}
