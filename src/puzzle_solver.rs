use crate::{
    bitcoin, hsm_cl, pedersen, pointcheval_sanders, secp256k1, NoMessage, NoTransaction, Params,
    Token, UnexpectedMessage, UnexpectedTransaction,
};
use rand::Rng;

#[derive(Debug, derive_more::From, serde::Serialize, strum_macros::Display)]
pub enum Message {
    Message0(Message0),
    Message1(Message1),
    Message2(Message2),
    Message3(Message3),
    Message4(Message4),
    Message5(Message5),
    Message6(Message6),
    Message7(Message7),
}

#[derive(Debug, serde::Serialize)]
pub struct Message0 {
    #[serde(with = "crate::serde::secp256k1_public_key")]
    pub X_s: secp256k1::PublicKey,
    #[serde(with = "crate::serde::bls12_381_g1affine")]
    pub C: pedersen::Commitment,
    pub pi_C: pedersen::Proof,
}

#[derive(Debug, serde::Serialize)]
pub struct Message1 {
    #[serde(with = "crate::serde::secp256k1_public_key")]
    pub X_t: secp256k1::PublicKey,
    #[serde(with = "crate::serde::secp256k1_signature")]
    pub sig_refund_t: secp256k1::Signature,
}

#[derive(Debug, serde::Serialize)]
pub struct Message2 {
    pub sig_token_blind: pointcheval_sanders::Signature,
}

#[derive(Debug, serde::Serialize)]
pub struct Message3 {
    #[serde(with = "crate::serde::bls12_381_scalar")]
    pub token: Token,
    pub sig_token_rand: pointcheval_sanders::Signature,
}

#[derive(Debug, serde::Serialize)]
pub struct Message4 {
    pub c_alpha_prime_prime: hsm_cl::Ciphertext,
}

#[derive(Debug, serde::Serialize)]
pub struct Message5 {
    #[serde(with = "crate::serde::secp256k1_public_key")]
    pub A_prime_prime: secp256k1::PublicKey,
}

#[derive(Debug, serde::Serialize)]
pub struct Message6 {
    pub sig_redeem_s: secp256k1::EncryptedSignature,
}

#[derive(Debug, serde::Serialize)]
pub struct Message7 {
    #[serde(with = "crate::serde::secp256k1_secret_key")]
    pub alpha_macron: secp256k1::SecretKey,
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
    Tumbler3(Tumbler3),
    Tumbler4(Tumbler4),
}

impl Tumbler {
    pub fn new(
        params: Params,
        HE: hsm_cl::KeyPair,
        PS: pointcheval_sanders::KeyPair,
        rng: &mut impl Rng,
    ) -> Self {
        let tumbler = Tumbler0::new(params, HE, PS, rng);

        tumbler.into()
    }

    pub fn transition_on_message(self, message: Message) -> anyhow::Result<Self> {
        let tumbler = match (self, message) {
            (Tumbler::Tumbler0(inner), Message::Message0(message)) => {
                inner.receive(message)?.into()
            }
            (Tumbler::Tumbler2(inner), Message::Message4(message)) => inner.receive(message).into(),
            (Tumbler::Tumbler3(inner), Message::Message6(message)) => {
                inner.receive(message)?.into()
            }
            (state, message) => anyhow::bail!(UnexpectedMessage::new(message, state)),
        };

        Ok(tumbler)
    }

    pub fn transition_on_transaction(
        self,
        transaction: FundTransaction,
        rng: &mut impl Rng,
    ) -> anyhow::Result<Self> {
        let tumbler = match self {
            Tumbler::Tumbler1(inner) => inner.receive(transaction, rng).into(),
            _ => anyhow::bail!(UnexpectedTransaction),
        };

        Ok(tumbler)
    }

    pub fn next_message(&self) -> anyhow::Result<Message> {
        let message = match self {
            Tumbler::Tumbler1(inner) => inner.next_message().into(),
            Tumbler::Tumbler2(inner) => inner.next_message().into(),
            Tumbler::Tumbler3(inner) => inner.next_message().into(),
            state => anyhow::bail!(NoMessage::new(state.clone())),
        };

        Ok(message)
    }

    pub fn redeem_transaction(&self) -> anyhow::Result<RedeemTransaction> {
        let transaction = match self {
            Tumbler::Tumbler4(inner) => inner.signed_redeem_transaction(),
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
    PS: pointcheval_sanders::KeyPair,
}

#[derive(Debug, Clone)]
pub struct Tumbler1 {
    transactions: bitcoin::Transactions,
    sig_refund_t: secp256k1::Signature,
    X_s: secp256k1::PublicKey,
    x_t: secp256k1::KeyPair,
    C: pedersen::Commitment,
    HE: hsm_cl::KeyPair,
    PS: pointcheval_sanders::KeyPair,
}

#[derive(Debug, Clone)]
pub struct Tumbler2 {
    sig_token_blind: pointcheval_sanders::Signature,
    transactions: bitcoin::Transactions,
    X_s: secp256k1::PublicKey,
    x_t: secp256k1::KeyPair,
    HE: hsm_cl::KeyPair,
}

#[derive(Debug, Clone)]
pub struct Tumbler3 {
    gamma: secp256k1::KeyPair,
    transactions: bitcoin::Transactions,
    X_s: secp256k1::PublicKey,
    x_t: secp256k1::KeyPair,
}

#[derive(Debug, Clone)]
pub struct Tumbler4 {
    signed_redeem_transaction: bitcoin::Transaction,
}

impl Tumbler0 {
    pub fn new(
        params: Params,
        HE: hsm_cl::KeyPair,
        PS: pointcheval_sanders::KeyPair,
        rng: &mut impl Rng,
    ) -> Self {
        Self {
            params,
            x_t: secp256k1::KeyPair::random(rng),
            HE,
            PS,
        }
    }

    pub fn receive(self, Message0 { X_s, C, pi_C }: Message0) -> anyhow::Result<Tumbler1> {
        pedersen::verify(
            &bls12_381::G1Affine::generator(),
            &self.PS.public_key.Y1,
            &C,
            pi_C,
        )?;

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

        let sig_refund_t = secp256k1::sign(transactions.refund_tx_digest, &self.x_t);

        Ok(Tumbler1 {
            transactions,
            sig_refund_t,
            X_s,
            x_t: self.x_t,
            C,
            HE: self.HE,
            PS: self.PS,
        })
    }
}

impl Tumbler1 {
    pub fn next_message(&self) -> Message1 {
        Message1 {
            sig_refund_t: self.sig_refund_t.clone(),
            X_t: self.x_t.to_pk(),
        }
    }

    pub fn receive(self, _fund_transaction: FundTransaction, rng: &mut impl Rng) -> Tumbler2 {
        // TODO: Verify transaction funds contract

        let sig_token_blind = pointcheval_sanders::sign(&self.PS, self.C, rng);

        Tumbler2 {
            sig_token_blind,
            x_t: self.x_t,
            X_s: self.X_s,
            transactions: self.transactions,
            HE: self.HE,
        }
    }
}

impl Tumbler2 {
    pub fn next_message(&self) -> Message2 {
        Message2 {
            sig_token_blind: self.sig_token_blind.clone(),
        }
    }

    pub fn receive(
        self,
        Message4 {
            c_alpha_prime_prime,
        }: Message4,
    ) -> Tumbler3 {
        let gamma = hsm_cl::decrypt(&self.HE, &c_alpha_prime_prime).into();

        Tumbler3 {
            transactions: self.transactions,
            x_t: self.x_t,
            X_s: self.X_s,
            gamma,
        }
    }
}

impl Tumbler3 {
    pub fn next_message(&self) -> Message5 {
        Message5 {
            A_prime_prime: self.gamma.to_pk(),
        }
    }

    pub fn receive(self, Message6 { sig_redeem_s }: Message6) -> anyhow::Result<Tumbler4> {
        let Self {
            transactions,
            x_t,
            X_s,
            gamma,
            ..
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

        Ok(Tumbler4 {
            signed_redeem_transaction,
        })
    }
}

impl Tumbler4 {
    pub fn signed_redeem_transaction(&self) -> RedeemTransaction {
        RedeemTransaction(self.signed_redeem_transaction.clone())
    }
}
