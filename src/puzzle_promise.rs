use crate::Lock;
use crate::{bitcoin, hsm_cl, secp256k1, NoMessage, NoTransaction, Params, UnexpectedMessage};
use anyhow::Context;
use rand::Rng;

#[derive(Debug, derive_more::From, serde::Serialize, strum_macros::Display)]
pub enum Message {
    Message0(Message0),
    Message1(Message1),
    Message2(Message2),
    Message3(Message3),
    Message4(Message4),
}

#[derive(Debug, serde::Serialize)]
pub struct Message0 {
    pub blinded_payment_proof: (),
}

#[derive(Debug, serde::Serialize)]
pub struct Message1 {
    #[serde(with = "crate::serde::secp256k1_public_key")]
    pub X_t: secp256k1::PublicKey,
    #[serde(with = "crate::serde::secp256k1_public_key")]
    pub A: secp256k1::PublicKey,
    pub c_alpha: hsm_cl::Ciphertext,
    pub pi_alpha: hsm_cl::Proof,
}

#[derive(Debug, serde::Serialize)]
pub struct Message2 {
    #[serde(with = "crate::serde::secp256k1_public_key")]
    pub X_r: secp256k1::PublicKey,
    #[serde(with = "crate::serde::secp256k1_signature")]
    pub sig_refund_r: secp256k1::Signature,
}

#[derive(Debug, serde::Serialize)]
pub struct Message3 {
    pub sig_redeem_t: secp256k1::EncryptedSignature,
}

#[derive(Debug, serde::Serialize)]
pub struct Message4 {
    pub l: Lock,
}

#[derive(Clone, Debug)]
pub struct FundTransaction(pub bitcoin::Transaction);

impl From<FundTransaction> for bitcoin::Transaction {
    fn from(fund_transaction: FundTransaction) -> Self {
        fund_transaction.0
    }
}

#[derive(Clone, Debug)]
pub struct RedeemTransaction(pub bitcoin::Transaction);

impl From<RedeemTransaction> for bitcoin::Transaction {
    fn from(redeem_transaction: RedeemTransaction) -> Self {
        redeem_transaction.0
    }
}

#[derive(Clone, Debug)]
pub struct RefundTransaction(pub bitcoin::Transaction);

impl From<RefundTransaction> for bitcoin::Transaction {
    fn from(refund_transaction: RefundTransaction) -> Self {
        refund_transaction.0
    }
}

#[derive(Debug, derive_more::From, Clone, strum_macros::Display)]
pub enum Tumbler {
    Tumbler0(Tumbler0),
    Tumbler1(Tumbler1),
    Tumbler2(Tumbler2),
}

impl Tumbler {
    pub fn new(params: Params, HE: hsm_cl::KeyPair, rng: &mut impl Rng) -> Self {
        Tumbler0::new(params, HE, rng).into()
    }

    pub fn transition(self, message: Message, rng: &mut impl Rng) -> anyhow::Result<Self> {
        let tumbler = match (self, message) {
            (Tumbler::Tumbler0(inner), Message::Message0(message)) => {
                inner.receive(message, rng)?.into()
            }
            (Tumbler::Tumbler1(inner), Message::Message2(message)) => {
                inner.receive(message, rng)?.into()
            }
            (state, message) => anyhow::bail!(UnexpectedMessage::new(message, state)),
        };

        Ok(tumbler)
    }

    pub fn next_message(&self) -> anyhow::Result<Message> {
        let message = match self {
            Tumbler::Tumbler1(inner) => inner.next_message().into(),
            Tumbler::Tumbler2(inner) => inner.next_message().into(),
            state => anyhow::bail!(NoMessage::new(state.clone())),
        };

        Ok(message)
    }

    pub fn fund_transaction(&self) -> anyhow::Result<FundTransaction> {
        let transaction = match self {
            Tumbler::Tumbler2(inner) => inner.unsigned_fund_transaction(),
            _ => anyhow::bail!(NoTransaction),
        };

        Ok(transaction)
    }

    pub fn refund_transaction(&self) -> anyhow::Result<RefundTransaction> {
        let transaction = match self {
            Tumbler::Tumbler2(inner) => inner.signed_refund_transaction(),
            _ => anyhow::bail!(NoTransaction),
        };

        Ok(transaction)
    }
}

#[derive(Debug, Clone)]
pub struct Tumbler0 {
    x_t: secp256k1::KeyPair,
    params: Params,
    HE: hsm_cl::KeyPair,
}

#[derive(Debug, Clone)]
pub struct Tumbler1 {
    x_t: secp256k1::KeyPair,
    a: secp256k1::KeyPair,
    params: Params,
    HE: hsm_cl::KeyPair,
    c_alpha: hsm_cl::Ciphertext,
    pi_alpha: hsm_cl::Proof,
}

#[derive(Debug, Clone)]
pub struct Tumbler2 {
    x_t: secp256k1::KeyPair,
    a: secp256k1::KeyPair,
    signed_refund_transaction: bitcoin::Transaction,
    transactions: bitcoin::Transactions,
    sig_redeem_t: secp256k1::EncryptedSignature,
}

impl Tumbler0 {
    pub fn new(params: Params, HE: hsm_cl::KeyPair, rng: &mut impl Rng) -> Self {
        let x_t = secp256k1::KeyPair::random(rng);

        Self { x_t, params, HE }
    }

    pub fn receive(
        self,
        Message0 { .. }: Message0,
        rng: &mut impl Rng,
    ) -> anyhow::Result<Tumbler1> {
        // verify payment proof before continuing

        let a = secp256k1::KeyPair::random(rng);
        let (c_alpha, pi_alpha) = hsm_cl::encrypt(&self.HE.to_pk(), &a);

        Ok(Tumbler1 {
            x_t: self.x_t,
            a,
            c_alpha,
            pi_alpha,
            params: self.params,
            HE: self.HE,
        })
    }
}

impl Tumbler1 {
    pub fn next_message(&self) -> Message1 {
        let X_t = self.x_t.to_pk();
        let A = self.a.to_pk();

        Message1 {
            X_t,
            A,
            c_alpha: self.c_alpha.clone(),
            pi_alpha: self.pi_alpha.clone(),
        }
    }

    pub fn receive(
        self,
        Message2 { X_r, sig_refund_r }: Message2,
        rng: &mut impl Rng,
    ) -> anyhow::Result<Tumbler2> {
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

        let sig_redeem_t = secp256k1::encsign(
            transactions.redeem_tx_digest,
            &self.x_t,
            &self.a.to_pk(),
            rng,
        );

        Ok(Tumbler2 {
            x_t: self.x_t,
            signed_refund_transaction,
            a: self.a,
            transactions,
            sig_redeem_t,
        })
    }
}

impl Tumbler2 {
    pub fn next_message(&self) -> Message3 {
        Message3 {
            sig_redeem_t: self.sig_redeem_t.clone(),
        }
    }

    pub fn unsigned_fund_transaction(&self) -> FundTransaction {
        FundTransaction(self.transactions.fund.clone())
    }
    pub fn signed_refund_transaction(&self) -> RefundTransaction {
        RefundTransaction(self.signed_refund_transaction.clone())
    }
    pub fn x_t(&self) -> &secp256k1::KeyPair {
        &self.x_t
    }
}
