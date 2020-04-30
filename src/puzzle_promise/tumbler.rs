use crate::bitcoin;
use crate::puzzle_promise::{Message0, Message1, Message2};
use crate::Params;
use crate::{hsm_cl, secp256k1};
use anyhow::Context;
use rand::Rng;

pub struct Tumbler0 {
    x_t: secp256k1::KeyPair,
    a: secp256k1::KeyPair,
    params: Params,
}

#[derive(Debug)]
pub struct Tumbler1 {
    x_t: secp256k1::KeyPair,
    a: secp256k1::KeyPair,
    signed_refund_transaction: bitcoin::Transaction,
    transactions: bitcoin::Transactions,
}

impl Tumbler0 {
    pub fn new(params: Params, rng: &mut impl Rng) -> Self {
        let x_t = secp256k1::KeyPair::random(rng);
        let a = secp256k1::KeyPair::random(rng);

        Self { x_t, a, params }
    }

    pub fn next_message(&self, HE: &impl hsm_cl::Encrypt) -> Message0 {
        let X_t = self.x_t.to_pk();
        let A = self.a.to_pk();
        let (c_alpha, pi_alpha) = HE.encrypt(&self.a);

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
