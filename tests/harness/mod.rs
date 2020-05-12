mod run_happy_path;
mod run_refund;

pub use self::run_happy_path::run_happy_path;
pub use self::run_refund::run_refund;
use a2l::{puzzle_promise, puzzle_solver, receiver::Receiver, sender::Sender};
use rand::Rng;

pub trait Transition<M>: Sized {
    fn transition(self, message: M, rng: &mut impl Rng) -> anyhow::Result<Self>;
}

pub trait NextMessage<M> {
    fn next_message(&self) -> anyhow::Result<M>;
}

pub trait MakeTransaction<T> {
    fn make_transaction(&self) -> anyhow::Result<T>;
}

impl Transition<puzzle_promise::Message> for puzzle_promise::Tumbler {
    fn transition(
        self,
        message: puzzle_promise::Message,
        rng: &mut impl Rng,
    ) -> anyhow::Result<Self> {
        self.transition(message, rng)
    }
}

impl NextMessage<puzzle_promise::Message> for puzzle_promise::Tumbler {
    fn next_message(&self) -> anyhow::Result<puzzle_promise::Message> {
        self.next_message()
    }
}

impl MakeTransaction<puzzle_promise::FundTransaction> for puzzle_promise::Tumbler {
    fn make_transaction(&self) -> anyhow::Result<puzzle_promise::FundTransaction> {
        self.fund_transaction()
    }
}

impl MakeTransaction<puzzle_promise::RefundTransaction> for puzzle_promise::Tumbler {
    fn make_transaction(&self) -> anyhow::Result<puzzle_promise::RefundTransaction> {
        self.refund_transaction()
    }
}

impl Transition<puzzle_solver::Message> for puzzle_solver::Tumbler {
    fn transition(self, message: puzzle_solver::Message, _: &mut impl Rng) -> anyhow::Result<Self> {
        self.transition_on_message(message)
    }
}

impl Transition<puzzle_solver::FundTransaction> for puzzle_solver::Tumbler {
    fn transition(
        self,
        transaction: puzzle_solver::FundTransaction,
        rng: &mut impl Rng,
    ) -> anyhow::Result<Self> {
        self.transition_on_transaction(transaction, rng)
    }
}

impl NextMessage<puzzle_solver::Message> for puzzle_solver::Tumbler {
    fn next_message(&self) -> anyhow::Result<puzzle_solver::Message> {
        self.next_message()
    }
}

impl MakeTransaction<puzzle_solver::RedeemTransaction> for puzzle_solver::Tumbler {
    fn make_transaction(&self) -> anyhow::Result<puzzle_solver::RedeemTransaction> {
        self.redeem_transaction()
    }
}

impl Transition<puzzle_promise::Message> for Receiver {
    fn transition(
        self,
        message: puzzle_promise::Message,
        rng: &mut impl Rng,
    ) -> anyhow::Result<Self> {
        self.transition_on_puzzle_promise_message(message, rng)
    }
}

impl Transition<puzzle_solver::Message> for Receiver {
    fn transition(self, message: puzzle_solver::Message, _: &mut impl Rng) -> anyhow::Result<Self> {
        self.transition_on_puzzle_solver_message(message)
    }
}

impl NextMessage<puzzle_promise::Message> for Receiver {
    fn next_message(&self) -> anyhow::Result<puzzle_promise::Message> {
        self.next_puzzle_promise_message()
    }
}

impl MakeTransaction<puzzle_promise::RedeemTransaction> for Receiver {
    fn make_transaction(&self) -> anyhow::Result<puzzle_promise::RedeemTransaction> {
        self.redeem_transaction()
    }
}

impl Transition<puzzle_promise::Message> for Sender {
    fn transition(
        self,
        message: puzzle_promise::Message,
        rng: &mut impl Rng,
    ) -> anyhow::Result<Self> {
        self.transition_on_puzzle_promise_message(message, rng)
    }
}

impl Transition<puzzle_solver::Message> for Sender {
    fn transition(
        self,
        message: puzzle_solver::Message,
        rng: &mut impl Rng,
    ) -> anyhow::Result<Self> {
        self.transition_on_puzzle_solver_message(message, rng)
    }
}

impl Transition<puzzle_solver::RedeemTransaction> for Sender {
    fn transition(
        self,
        transaction: puzzle_solver::RedeemTransaction,
        _: &mut impl Rng,
    ) -> anyhow::Result<Self> {
        self.transition_on_transaction(transaction)
    }
}

impl MakeTransaction<puzzle_solver::FundTransaction> for Sender {
    fn make_transaction(&self) -> anyhow::Result<puzzle_solver::FundTransaction> {
        self.unsigned_fund_transaction()
    }
}

impl MakeTransaction<puzzle_solver::RefundTransaction> for Sender {
    fn make_transaction(&self) -> anyhow::Result<puzzle_solver::RefundTransaction> {
        self.signed_refund_transaction()
    }
}

impl NextMessage<puzzle_solver::Message> for Sender {
    fn next_message(&self) -> anyhow::Result<puzzle_solver::Message> {
        self.next_puzzle_solver_message()
    }
}

pub fn random_p2wpkh() -> ::bitcoin::Address {
    ::bitcoin::Address::p2wpkh(
        &::bitcoin::PublicKey::from_private_key(
            &::bitcoin::secp256k1::Secp256k1::signing_only(),
            &::bitcoin::PrivateKey {
                compressed: true,
                network: ::bitcoin::Network::Regtest,
                key: ::bitcoin::secp256k1::SecretKey::new(
                    &mut ::bitcoin::secp256k1::rand::thread_rng(),
                ),
            },
        ),
        ::bitcoin::Network::Regtest,
    )
}
