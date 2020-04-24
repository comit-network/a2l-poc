use crate::bitcoin;
use crate::dummy_hsm_cl as hsm_cl;
use crate::puzzle_solver::{Message0, Message1, Message2, Message3};
use crate::secp256k1;
use crate::Params;

pub struct Tumbler0 {
    x_t: secp256k1::KeyPair,
    params: Params,
}

pub struct Tumbler1 {
    params: Params,
    x_t: secp256k1::KeyPair,
    X_s: secp256k1::PublicKey,
    gamma: secp256k1::KeyPair,
}

pub struct Tumbler2 {
    signed_redeem_transaction: bitcoin::Transaction,
}

impl Tumbler0 {
    pub fn new(params: Params, x_t: secp256k1::KeyPair) -> Self {
        Self { x_t, params }
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
        HE: &impl hsm_cl::Decrypt,
    ) -> Tumbler1 {
        let gamma = HE.decrypt(&self.x_t, &c_alpha_prime_prime).into();

        Tumbler1 {
            params: self.params,
            x_t: self.x_t,
            X_s,
            gamma,
        }
    }
}

impl Tumbler1 {
    pub fn next_message(&self) -> Message2 {
        let A_prime_prime = self.gamma.to_pk();

        let fund_transaction = bitcoin::make_fund_transaction(
            self.params.partial_fund_transaction.clone(),
            self.params.amount,
            &self.X_s,
            &self.x_t.to_pk(),
        );

        let (_, digest) = bitcoin::make_spend_transaction(
            &fund_transaction,
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

    pub fn receive(self, Message3 { sig_redeem_s }: Message3) -> anyhow::Result<Tumbler2> {
        let Self {
            params:
                Params {
                    amount,
                    partial_fund_transaction,
                    redeem_identity,
                    ..
                },
            x_t,
            X_s,
            gamma,
        } = self;

        let signed_redeem_transaction = {
            let fund_transaction = bitcoin::make_fund_transaction(
                partial_fund_transaction,
                amount,
                &X_s,
                &x_t.to_pk(),
            );

            let (redeem_transaction, digest) = bitcoin::make_spend_transaction(
                dbg!(&fund_transaction),
                amount,
                &redeem_identity,
                0,
            );

            let sig_redeem_s = secp256k1::decsig(&gamma, &sig_redeem_s);
            secp256k1::verify(digest, &sig_redeem_s, &X_s)?;

            let sig_redeem_t = secp256k1::sign(digest, &x_t);

            bitcoin::complete_spend_transaction(
                redeem_transaction,
                (X_s, sig_redeem_s),
                (x_t.to_pk(), sig_redeem_t),
            )?
        };

        Ok(Tumbler2 {
            signed_redeem_transaction,
        })
    }
}

impl Tumbler2 {
    pub fn signed_redeem_transaction(&self) -> &bitcoin::Transaction {
        &self.signed_redeem_transaction
    }
}
