use crate::hsm_cl::Decrypt;
use crate::puzzle_solver::{Message0, Message1, Message2, Message3};
use crate::{bitcoin, UnexpectedMessage};
use crate::{hsm_cl, NoMessage};
use crate::{secp256k1, Transition};
use crate::{NextMessage, Params};
use rand::Rng;

#[derive(Debug, derive_more::From)]
pub enum Tumbler {
    Tumbler0(Tumbler0),
    Tumbler1(Tumbler1),
    Tumbler2(Tumbler2),
}

impl Tumbler {
    pub fn new(params: Params, HE: hsm_cl::KeyPair, rng: &mut impl Rng) -> Self {
        let tumbler = Tumbler0::new(params, HE, rng);

        tumbler.into()
    }

    pub fn transition(self, message: In) -> anyhow::Result<Self> {
        let tumbler = match (self, message) {
            (Tumbler::Tumbler0(inner), In::Message1(message)) => inner.receive(message).into(),
            (Tumbler::Tumbler1(inner), In::Message3(message)) => inner.receive(message)?.into(),
            _ => anyhow::bail!(UnexpectedMessage),
        };

        Ok(tumbler)
    }

    pub fn next_message(&self) -> Result<Out, NoMessage> {
        let message = match self {
            Tumbler::Tumbler0(inner) => inner.next_message().into(),
            Tumbler::Tumbler1(inner) => inner.next_message().into(),
            _ => return Err(NoMessage),
        };

        Ok(message)
    }
}

impl Transition for Tumbler {
    type Message = In;

    fn transition<R: Rng>(self, message: Self::Message, _: &mut R) -> anyhow::Result<Self> {
        self.transition(message)
    }
}

impl NextMessage for Tumbler {
    type Message = Out;

    fn next_message<R: Rng>(&self, _: &mut R) -> Result<Self::Message, NoMessage> {
        self.next_message()
    }
}

#[derive(Debug)]
pub struct Tumbler0 {
    x_t: secp256k1::KeyPair,
    params: Params,
    HE: hsm_cl::KeyPair,
}

#[derive(Debug)]
pub struct Tumbler1 {
    transactions: bitcoin::Transactions,
    x_t: secp256k1::KeyPair,
    X_s: secp256k1::PublicKey,
    gamma: secp256k1::KeyPair,
}

#[derive(Debug)]
pub struct Tumbler2 {
    signed_redeem_transaction: bitcoin::Transaction,
}

#[derive(Debug, derive_more::From)]
pub enum In {
    Message1(Message1),
    Message3(Message3),
}

#[derive(Debug, derive_more::From)]
pub enum Out {
    Message0(Message0),
    Message2(Message2),
}

pub struct Return {
    pub signed_redeem_transaction: bitcoin::Transaction,
}

impl From<Tumbler2> for Return {
    fn from(tumbler: Tumbler2) -> Self {
        Return {
            signed_redeem_transaction: tumbler.signed_redeem_transaction,
        }
    }
}

impl Tumbler0 {
    pub fn new(params: Params, HE: hsm_cl::KeyPair, rng: &mut impl Rng) -> Self {
        Self {
            params,
            x_t: secp256k1::KeyPair::random(rng),
            HE,
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
        let gamma = self.HE.decrypt(&c_alpha_prime_prime).into();

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
        })
    }
}

impl Tumbler2 {
    pub fn signed_redeem_transaction(&self) -> &bitcoin::Transaction {
        &self.signed_redeem_transaction
    }
}
