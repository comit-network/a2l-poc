use crate::puzzle_solver::{Message, Message4};
use crate::UnexpectedMessage;
use crate::{bitcoin, Transition};
use crate::{secp256k1, NextMessage, NoMessage};
use anyhow::Context;
use rand::Rng;
use std::convert::TryFrom;

#[derive(Debug)]
pub struct Receiver0 {
    X_r: secp256k1::PublicKey,
    X_t: secp256k1::PublicKey,
    unsigned_redeem_transaction: bitcoin::Transaction,
    sig_redeem_t: secp256k1::EncryptedSignature,
    sig_redeem_r: secp256k1::Signature,
    beta: secp256k1::KeyPair,
    redeem_tx_digest: bitcoin::SigHash,
}

#[derive(Debug)]
pub struct Receiver1 {
    signed_redeem_transaction: bitcoin::Transaction,
}

impl Receiver0 {
    pub fn new(
        X_r: secp256k1::PublicKey,
        X_t: secp256k1::PublicKey,
        unsigned_redeem_transaction: bitcoin::Transaction,
        sig_redeem_t: secp256k1::EncryptedSignature,
        sig_redeem_r: secp256k1::Signature,
        beta: secp256k1::KeyPair,
        redeem_tx_digest: bitcoin::SigHash,
    ) -> Self {
        Self {
            X_r,
            X_t,
            unsigned_redeem_transaction,
            sig_redeem_t,
            sig_redeem_r,
            beta,
            redeem_tx_digest,
        }
    }

    pub fn receive(self, Message4 { alpha_macron }: Message4) -> anyhow::Result<Receiver1> {
        let Self {
            X_r,
            X_t,
            unsigned_redeem_transaction,
            sig_redeem_t,
            sig_redeem_r,
            beta,
            redeem_tx_digest,
        } = self;

        let alpha = {
            let alpha_macron: secp256k1::Scalar = alpha_macron.into();
            let beta: secp256k1::Scalar = beta.into_sk().into();

            alpha_macron * beta.inv()
        };

        let sig_redeem_t = secp256k1::decsig(&secp256k1::KeyPair::try_from(alpha)?, &sig_redeem_t);

        secp256k1::verify(redeem_tx_digest, &sig_redeem_t, &X_t)
            .context("failed to verify tumbler redeem signature after decryption")?;

        let signed_redeem_transaction = bitcoin::complete_spend_transaction(
            unsigned_redeem_transaction,
            (X_t, sig_redeem_t),
            (X_r, sig_redeem_r),
        )?;

        Ok(Receiver1 {
            signed_redeem_transaction,
        })
    }
}

impl Receiver1 {
    pub fn signed_redeem_transaction(&self) -> &bitcoin::Transaction {
        &self.signed_redeem_transaction
    }
}
