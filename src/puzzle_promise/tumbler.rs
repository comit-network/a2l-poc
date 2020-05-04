use crate::bitcoin;
use crate::hsm_cl::Encrypt;
use crate::puzzle_promise::{Message0, Message1, Message2};
use crate::Params;
use crate::{hsm_cl, secp256k1};
use anyhow::Context;
use rand::Rng;

pub struct Tumbler0 {
    x_t: secp256k1::KeyPair,
    a: secp256k1::KeyPair,
    params: Params,
    HE: hsm_cl::KeyPair,
}

#[derive(Debug)]
pub struct Tumbler1 {
    x_t: secp256k1::KeyPair,
    a: secp256k1::KeyPair,
    signed_refund_transaction: bitcoin::Transaction,
    transactions: bitcoin::Transactions,
}

#[derive(Debug)]
pub enum In {
    Start,
    Message1(Message1),
}

#[derive(Debug)]
pub enum Out {
    WaitingForMessage1,
    Message0(Message0),
    Message2(Message2),
}

#[derive(Debug)]
pub struct Return {
    x_t: secp256k1::KeyPair,
    signed_refund_transaction: bitcoin::Transaction,
    unsigned_fund_transaction: bitcoin::Transaction,
}

impl From<Tumbler1> for Return {
    fn from(tumbler: Tumbler1) -> Self {
        Return {
            x_t: tumbler.x_t,
            signed_refund_transaction: tumbler.signed_refund_transaction,
            unsigned_fund_transaction: tumbler.transactions.fund,
        }
    }
}

impl Tumbler0 {
    pub fn new(params: Params, rng: &mut impl Rng, HE: hsm_cl::KeyPair) -> Self {
        let x_t = secp256k1::KeyPair::random(rng);
        let a = secp256k1::KeyPair::random(rng);

        Self { x_t, a, params, HE }
    }

    pub fn next_message(&self) -> Message0 {
        let X_t = self.x_t.to_pk();
        let A = self.a.to_pk();
        let (c_alpha, pi_alpha) = self.HE.to_pk().encrypt(&self.a);

        Message0 {
            X_t,
            A,
            c_alpha,
            pi_alpha,
        }
    }

    pub fn receive(self, Message1 { X_r, sig_refund_r }: Message1) -> anyhow::Result<Tumbler1> {
        let transactions = bitcoin::make_transactions(
            self.params.partial_fund_transaction.clone(),
            self.params.tumbler_receiver_joint_output_value(),
            self.params.tumbler_receiver_joint_output_takeout(),
            &self.x_t.to_pk(),
            &X_r,
            self.params.expiry,
            &self.params.redeem_identity,
            &self.params.refund_identity,
        );

        let signed_refund_transaction = {
            secp256k1::verify(transactions.refund_tx_digest, &sig_refund_r, &X_r)
                .context("failed to verify receiver refund signature")?;

            let sig_refund_t = secp256k1::sign(transactions.refund_tx_digest, &self.x_t);

            bitcoin::complete_spend_transaction(
                transactions.refund.clone(),
                (self.x_t.to_pk(), sig_refund_t),
                (X_r, sig_refund_r),
            )?
        };

        Ok(Tumbler1 {
            x_t: self.x_t,
            signed_refund_transaction,
            a: self.a,
            transactions,
        })
    }
}

impl Tumbler1 {
    pub fn next_message(&self, rng: &mut impl Rng) -> Message2 {
        let sig_redeem_t = secp256k1::encsign(
            self.transactions.redeem_tx_digest,
            &self.x_t,
            &self.a.to_pk(),
            rng,
        );

        Message2 { sig_redeem_t }
    }

    pub fn unsigned_fund_transaction(&self) -> &bitcoin::Transaction {
        &self.transactions.fund
    }
    pub fn signed_refund_transaction(&self) -> &bitcoin::Transaction {
        &self.signed_refund_transaction
    }
    pub fn x_t(&self) -> &secp256k1::KeyPair {
        &self.x_t
    }
}