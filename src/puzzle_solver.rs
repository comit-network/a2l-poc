use crate::bitcoin;
use crate::dummy_hsm_cl as hsm_cl;
use crate::dummy_hsm_cl::Decrypt as _;
use crate::dummy_hsm_cl::Multiply as _;
use crate::secp256k1;
use crate::Lock;
use crate::Params;
use anyhow::Context as _;
use fehler::{throw, throws};
use rand::Rng;
use std::convert::{TryFrom, TryInto};

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

    pub fn receive(
        self,
        Message1 {
            X_s,
            c_alpha_prime_prime,
        }: Message1,
    ) -> Tumbler1 {
        let gamma = self.hsm_cl.decrypt(&self.x_t, &c_alpha_prime_prime).into();

        Tumbler1 {
            params: self.params,
            x_t: self.x_t,
            X_s,
            gamma,
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
    pub fn new(
        params: Params,
        Lock {
            c_alpha_prime,
            A_prime,
        }: Lock,
        hsm_cl: hsm_cl::PublicKey,
        rng: &mut impl Rng,
    ) -> Self {
        Self {
            params,
            x_s: secp256k1::KeyPair::random(rng),
            hsm_cl,
            c_alpha_prime,
            A_prime,
        }
    }

    pub fn receive(self, Message0 { X_t }: Message0, rng: &mut impl Rng) -> Sender1 {
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

    #[throws(anyhow::Error)]
    pub fn receive(
        self,
        Message2 {
            A_prime_prime,
            sig_refund_t,
        }: Message2,
        rng: &mut impl Rng,
    ) -> Sender2 {
        let A_prime_tau = self.hsm_cl.multiply(&self.A_prime, &self.tau);
        if A_prime_tau != A_prime_prime {
            throw!(AptNotEqualApp)
        }

        let fund_transaction = bitcoin::make_fund_transaction(
            self.params.partial_fund_transaction,
            self.params.amount,
            &self.x_s.to_pk(),
            &self.X_t,
        );

        let (refund_transaction, sig_refund_s) = {
            let (transaction, digest) = bitcoin::make_spend_transaction(
                &fund_transaction,
                self.params.amount,
                &self.params.refund_identity,
                self.params.expiry,
            );

            secp256k1::verify(digest, &sig_refund_t, &self.X_t)
                .context("failed to verify tumbler refund signature")?;

            let signature = secp256k1::sign(digest, &self.x_s);

            (transaction, signature)
        };

        let sig_redeem_s = {
            let (_, digest) = bitcoin::make_spend_transaction(
                &fund_transaction,
                self.params.amount,
                &self.params.redeem_identity,
                0,
            );

            secp256k1::encsign(digest, &self.x_s, &A_prime_prime, rng)
        };

        Sender2 {
            unsigned_fund_transaction: fund_transaction,
            signed_refund_transaction: bitcoin::complete_spend_transaction(
                refund_transaction,
                (self.x_s.to_pk(), sig_refund_s),
                (self.X_t, sig_refund_t),
            )?,
            sig_redeem_s,
            A_prime_prime,
            tau: self.tau,
        }
    }
}

pub struct Sender2 {
    unsigned_fund_transaction: bitcoin::Transaction,
    signed_refund_transaction: bitcoin::Transaction,
    sig_redeem_s: secp256k1::EncryptedSignature,
    A_prime_prime: secp256k1::PublicKey,
    tau: secp256k1::KeyPair,
}

impl Sender2 {
    pub fn next_message(&self) -> Message3 {
        Message3 {
            sig_redeem_s: self.sig_redeem_s.clone(),
        }
    }

    #[throws(anyhow::Error)]
    pub fn receive(self, redeem_transaction: bitcoin::Transaction) -> Sender3 {
        let Self {
            sig_redeem_s: encrypted_signature,
            A_prime_prime,
            tau,
            ..
        } = self;

        let decrypted_signature =
            bitcoin::extract_signature_by_key(redeem_transaction, &A_prime_prime)?;

        let gamma =
            secp256k1::recover(&A_prime_prime, &encrypted_signature, &decrypted_signature)??;
        let alpha_macron = {
            let gamma: secp256k1::Scalar = gamma.into_sk().into();
            let tau: secp256k1::Scalar = tau.into_sk().into();

            gamma * tau.inv()
        };

        Sender3 {
            alpha_macron: alpha_macron.try_into()?,
        }
    }

    pub fn unsigned_fund_transaction(&self) -> bitcoin::Transaction {
        self.unsigned_fund_transaction.clone()
    }

    pub fn signed_refund_transaction(&self) -> bitcoin::Transaction {
        self.signed_refund_transaction.clone()
    }
}

pub struct Sender3 {
    alpha_macron: secp256k1::KeyPair,
}

impl Sender3 {
    pub fn next_message(&self) -> Message4 {
        Message4 {
            alpha_macron: self.alpha_macron.to_sk(),
        }
    }

    pub fn output(self) -> SenderOutput {
        SenderOutput {
            alpha_macron: self.alpha_macron,
        }
    }
}

pub struct SenderOutput {
    pub alpha_macron: secp256k1::KeyPair,
}

#[derive(thiserror::Error, Debug)]
#[error("(A')^tau != A''")]
pub struct AptNotEqualApp;

pub struct Tumbler1 {
    params: Params,
    x_t: secp256k1::KeyPair,
    X_s: secp256k1::PublicKey,
    gamma: secp256k1::KeyPair,
}

impl Tumbler1 {
    pub fn next_message(&self) -> Message2 {
        let A_prime_prime = self.gamma.to_pk();

        let (_, digest) = bitcoin::make_spend_transaction(
            &self.params.partial_fund_transaction,
            self.params.amount,
            &self.params.refund_identity,
            self.params.expiry,
        );
        let sig_refund_t = secp256k1::sign(digest, &self.x_t);

        Message2 {
            A_prime_prime,
            sig_refund_t,
        }
    }

    #[throws(anyhow::Error)]
    pub fn receive(self, Message3 { sig_redeem_s }: Message3) -> Tumbler2 {
        let (redeem_transaction, digest) = bitcoin::make_spend_transaction(
            &self.params.partial_fund_transaction,
            self.params.amount,
            &self.params.redeem_identity,
            0,
        );

        let sig_redeem_s = secp256k1::decsig(&self.gamma, &sig_redeem_s);
        secp256k1::verify(digest, &sig_redeem_s, &self.X_s)?;

        let sig_redeem_t = secp256k1::sign(digest, &self.x_t);

        Tumbler2 {
            signed_redeem_transaction: bitcoin::complete_spend_transaction(
                redeem_transaction,
                (self.x_t.to_pk(), sig_redeem_t),
                (self.X_s, sig_redeem_s),
            )?,
        }
    }
}

pub struct Tumbler2 {
    signed_redeem_transaction: bitcoin::Transaction,
}

impl Tumbler2 {
    pub fn output(self) -> TumblerOutput {
        TumblerOutput {
            signed_redeem_transaction: self.signed_redeem_transaction,
        }
    }
}

pub struct TumblerOutput {
    pub signed_redeem_transaction: bitcoin::Transaction,
}

pub struct Receiver0 {
    X_r: secp256k1::PublicKey,
    X_t: secp256k1::PublicKey,
    unsigned_redeem_transaction: bitcoin::Transaction,
    sig_redeem_t: secp256k1::EncryptedSignature,
    sig_redeem_r: secp256k1::Signature,
    beta: secp256k1::KeyPair,
}

impl Receiver0 {
    pub fn new(
        X_r: secp256k1::PublicKey,
        X_t: secp256k1::PublicKey,
        unsigned_redeem_transaction: bitcoin::Transaction,
        sig_redeem_t: secp256k1::EncryptedSignature,
        sig_redeem_r: secp256k1::Signature,
        beta: secp256k1::KeyPair,
    ) -> Self {
        Self {
            X_r,
            X_t,
            unsigned_redeem_transaction,
            sig_redeem_t,
            sig_redeem_r,
            beta,
        }
    }

    #[throws(anyhow::Error)]
    pub fn receive(self, Message4 { alpha_macron }: Message4) -> Receiver1 {
        let Self {
            X_r,
            X_t,
            unsigned_redeem_transaction,
            sig_redeem_t,
            sig_redeem_r,
            beta,
        } = self;

        let alpha = {
            let alpha_macron: secp256k1::Scalar = alpha_macron.into();
            let beta: secp256k1::Scalar = beta.into_sk().into();

            alpha_macron * beta.inv()
        };

        let sig_redeem_t = secp256k1::decsig(&secp256k1::KeyPair::try_from(alpha)?, &sig_redeem_t);

        let signed_redeem_transaction = bitcoin::complete_spend_transaction(
            unsigned_redeem_transaction,
            (X_r, sig_redeem_r),
            (X_t, sig_redeem_t),
        )?;

        Receiver1 {
            signed_redeem_transaction,
        }
    }
}

pub struct Receiver1 {
    signed_redeem_transaction: bitcoin::Transaction,
}

impl Receiver1 {
    pub fn signed_redeem_transaction(&self) -> &bitcoin::Transaction {
        &self.signed_redeem_transaction
    }
}

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
