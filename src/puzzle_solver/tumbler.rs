use crate::bitcoin;
use crate::dummy_hsm_cl as hsm_cl;
use crate::puzzle_solver::{Message0, Message1, Message2, Message3};
use crate::secp256k1;
use crate::Params;

pub struct Tumbler0 {
    x_t: secp256k1::KeyPair,
    params: Params,
    signed_refund_transaction: bitcoin::Transaction,
}

pub struct Tumbler1 {
    transactions: bitcoin::Transactions,
    x_t: secp256k1::KeyPair,
    X_s: secp256k1::PublicKey,
    gamma: secp256k1::KeyPair,
    signed_refund_transaction: bitcoin::Transaction,
}

pub struct Tumbler2 {
    signed_redeem_transaction: bitcoin::Transaction,
    signed_refund_transaction: bitcoin::Transaction,
}

impl Tumbler0 {
    pub fn new(
        params: Params,
        x_t: secp256k1::KeyPair,
        signed_refund_transaction: bitcoin::Transaction,
    ) -> Self {
        Self {
            x_t,
            params,
            signed_refund_transaction,
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
        HE: &impl hsm_cl::Decrypt,
    ) -> Tumbler1 {
        let gamma = HE.decrypt(&self.x_t, &c_alpha_prime_prime).into();

        let transactions = bitcoin::make_transactions(
            self.params.partial_fund_transaction.clone(),
            self.params.sender_tumbler_joint_output_value(),
            self.params.sender_tumbler_joint_output_takeout(),
            &X_s,
            &self.x_t.to_pk(),
            self.params.expiry,
            &self.params.redeem_identity,
            &self.params.refund_identity,
        );

        Tumbler1 {
            transactions,
            x_t: self.x_t,
            X_s,
            gamma,
            signed_refund_transaction: self.signed_refund_transaction,
        }
    }
}

impl Tumbler1 {
    pub fn next_message(&self) -> Message2 {
        let A_prime_prime = self.gamma.to_pk();
        let sig_refund_t = secp256k1::sign(self.transactions.refund_tx_digest, &self.x_t);

        Message2 {
            A_prime_prime,
            sig_refund_t,
        }
    }

    pub fn receive(self, Message3 { sig_redeem_s }: Message3) -> anyhow::Result<Tumbler2> {
        let Self {
            transactions,
            x_t,
            X_s,
            gamma,
            signed_refund_transaction,
        } = self;

        let signed_redeem_transaction = {
            let sig_redeem_s = secp256k1::decsig(&gamma, &sig_redeem_s);
            secp256k1::verify(transactions.redeem_tx_digest, &sig_redeem_s, &X_s)?;

            let sig_redeem_t = secp256k1::sign(transactions.redeem_tx_digest, &x_t);

            bitcoin::complete_spend_transaction(
                transactions.redeem,
                (X_s, sig_redeem_s),
                (x_t.to_pk(), sig_redeem_t),
            )?
        };

        Ok(Tumbler2 {
            signed_redeem_transaction,
            signed_refund_transaction,
        })
    }
}

impl Tumbler2 {
    pub fn signed_redeem_transaction(&self) -> &bitcoin::Transaction {
        &self.signed_redeem_transaction
    }

    pub fn signed_refund_transaction(&self) -> &bitcoin::Transaction {
        &self.signed_refund_transaction
    }
}
