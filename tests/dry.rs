pub mod harness;

use crate::harness::{run_happy_path, FundTransaction, NextMessage, RedeemTransaction, Transition};
use a2l::{
    bitcoin::random_p2wpkh,
    hsm_cl, puzzle_promise, puzzle_solver,
    receiver::{self, Receiver},
    sender::{self, Sender},
    NoMessage, Params,
};
use anyhow::bail;
use rand::{thread_rng, Rng};
use serde::Serialize;

#[test]
fn dry_happy_path() {
    let he_keypair = hsm_cl::keygen(b"A2L-PoC");

    let blockchain = Blockchain::default();

    let tumble_amount = bitcoin::Amount::from_sat(10_000_000);
    let spend_transaction_fee_per_wu = bitcoin::Amount::from_sat(10);
    let tumbler_fee = bitcoin::Amount::from_sat(10_000);

    let (tumbler_promise, receiver) = make_puzzle_promise_actors(
        tumble_amount,
        spend_transaction_fee_per_wu,
        he_keypair.clone(),
        he_keypair.to_pk(),
    );

    let (tumbler_solver, sender) = make_puzzle_solver_actors(
        tumble_amount,
        spend_transaction_fee_per_wu,
        tumbler_fee,
        he_keypair,
    );

    let res = run_happy_path(
        tumbler_promise,
        tumbler_solver,
        sender,
        receiver,
        blockchain,
        &mut thread_rng(),
    );

    assert!(res.is_ok());
}

#[test]
fn happy_path_fees() -> anyhow::Result<()> {
    let he_keypair = hsm_cl::keygen(b"A2L-PoC");

    let blockchain = Blockchain::default();

    let tumble_amount = bitcoin::Amount::from_sat(10_000_000);
    let spend_transaction_fee_per_wu = bitcoin::Amount::from_sat(10);
    let tumbler_fee = bitcoin::Amount::from_sat(10_000);

    let (tumbler_promise, receiver) = make_puzzle_promise_actors(
        tumble_amount,
        spend_transaction_fee_per_wu,
        he_keypair.clone(),
        he_keypair.to_pk(),
    );

    let (tumbler_solver, sender) = make_puzzle_solver_actors(
        tumble_amount,
        spend_transaction_fee_per_wu,
        tumbler_fee,
        he_keypair,
    );

    let (_, _, _, _, blockchain) = run_happy_path(
        tumbler_promise,
        tumbler_solver,
        sender,
        receiver,
        blockchain,
        &mut thread_rng(),
    )?;

    let (tumbler_fund, sender_fund, tumbler_redeem, receiver_redeem) = match blockchain.0.as_slice()
    {
        [tumbler_fund, sender_fund, tumbler_redeem, receiver_redeem] => {
            (tumbler_fund, sender_fund, tumbler_redeem, receiver_redeem)
        }
        _ => bail!("wrong transactions in blockchain"),
    };

    assert_eq!(
        bitcoin::Amount::from_sat(sender_fund.output[0].value),
        tumble_amount
            + tumbler_fee
            + spend_transaction_fee_per_wu * a2l::bitcoin::MAX_SATISFACTION_WEIGHT
    );
    assert_eq!(
        bitcoin::Amount::from_sat(tumbler_redeem.output[0].value),
        tumble_amount + tumbler_fee
    );
    assert_eq!(
        bitcoin::Amount::from_sat(tumbler_fund.output[0].value),
        tumble_amount + spend_transaction_fee_per_wu * a2l::bitcoin::MAX_SATISFACTION_WEIGHT
    );
    assert_eq!(
        bitcoin::Amount::from_sat(receiver_redeem.output[0].value),
        tumble_amount
    );

    Ok(())
}

#[test]
fn redeem_transaction_size() -> anyhow::Result<()> {
    let he_keypair = hsm_cl::keygen(b"A2L-PoC");

    let blockchain = Blockchain::default();

    let tumble_amount = bitcoin::Amount::from_sat(10_000_000);
    let spend_transaction_fee_per_wu = bitcoin::Amount::from_sat(10);
    let tumbler_fee = bitcoin::Amount::from_sat(10_000);

    let (tumbler_promise, receiver) = make_puzzle_promise_actors(
        tumble_amount,
        spend_transaction_fee_per_wu,
        he_keypair.clone(),
        he_keypair.to_pk(),
    );

    let (tumbler_solver, sender) = make_puzzle_solver_actors(
        tumble_amount,
        spend_transaction_fee_per_wu,
        tumbler_fee,
        he_keypair,
    );

    let (_, _, _, _, blockchain) = run_happy_path(
        tumbler_promise,
        tumbler_solver,
        sender,
        receiver,
        blockchain,
        &mut thread_rng(),
    )?;

    let (tumbler_redeem, receiver_redeem) = match blockchain.0.as_slice() {
        [_, _, tumbler_redeem, receiver_redeem] => (tumbler_redeem, receiver_redeem),
        _ => bail!("wrong transactions in blockchain"),
    };

    let redeem_tx_weight = tumbler_redeem.get_weight() + receiver_redeem.get_weight();
    let max_expected_weight = 1095;

    assert!(max_expected_weight >= redeem_tx_weight);

    Ok(())
}

#[test]
fn protocol_bandwidth() -> anyhow::Result<()> {
    let he_keypair = hsm_cl::keygen(b"A2L-PoC");

    let blockchain = Blockchain::default();

    let tumble_amount = bitcoin::Amount::from_sat(10_000_000);
    let spend_transaction_fee_per_wu = bitcoin::Amount::from_sat(10);
    let tumbler_fee = bitcoin::Amount::from_sat(10_000);

    let (tumbler_promise, receiver) = make_puzzle_promise_actors(
        tumble_amount,
        spend_transaction_fee_per_wu,
        he_keypair.clone(),
        he_keypair.to_pk(),
    );
    let (tumbler_solver, sender) = make_puzzle_solver_actors(
        tumble_amount,
        spend_transaction_fee_per_wu,
        tumbler_fee,
        he_keypair,
    );

    let tumbler_promise = BandwidthRecorder::new(tumbler_promise);
    let receiver = BandwidthRecorder::new(receiver);
    let tumbler_solver = BandwidthRecorder::new(tumbler_solver);
    let sender = BandwidthRecorder::new(sender);

    let (tumbler_promise, tumbler_solver, sender, receiver, _) = run_happy_path(
        tumbler_promise,
        tumbler_solver,
        sender,
        receiver,
        blockchain,
        &mut thread_rng(),
    )?;

    let total_bandwidth = tumbler_promise.bandwidth_used
        + tumbler_solver.bandwidth_used
        + sender.bandwidth_used
        + receiver.bandwidth_used;
    let max_expected_bandwidth = 7240;

    assert!(
        max_expected_bandwidth >= total_bandwidth,
        "{} >= {}",
        max_expected_bandwidth,
        total_bandwidth
    );

    Ok(())
}

#[derive(Default, Debug)]
struct Blockchain(Vec<bitcoin::Transaction>);

impl Transition<bitcoin::Transaction> for Blockchain {
    fn transition(
        self,
        transaction: bitcoin::Transaction,
        _rng: &mut impl rand::Rng,
    ) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let mut vec = self.0;
        vec.push(transaction);
        Ok(Blockchain(vec))
    }
}

fn make_puzzle_promise_actors(
    tumble_amount: bitcoin::Amount,
    spend_transaction_fee_per_wu: bitcoin::Amount,
    he_keypair: hsm_cl::KeyPair,
    he_publickey: hsm_cl::PublicKey,
) -> (puzzle_promise::Tumbler, Receiver) {
    let params = make_dummy_params(
        tumble_amount,
        spend_transaction_fee_per_wu,
        bitcoin::Amount::from_sat(0),
    );

    let tumbler = puzzle_promise::Tumbler::new(params.clone(), he_keypair, &mut thread_rng());
    let receiver = receiver::Receiver::new(params, &mut thread_rng(), he_publickey);

    (tumbler, receiver)
}

fn make_puzzle_solver_actors(
    tumble_amount: bitcoin::Amount,
    spend_transaction_fee_per_wu: bitcoin::Amount,
    tumbler_fee: bitcoin::Amount,
    he_keypair: hsm_cl::KeyPair,
) -> (puzzle_solver::Tumbler, Sender) {
    let params = make_dummy_params(tumble_amount, spend_transaction_fee_per_wu, tumbler_fee);

    let tumbler = puzzle_solver::Tumbler::new(params.clone(), he_keypair, &mut thread_rng());
    let sender = sender::Sender::new(params, &mut thread_rng());

    (tumbler, sender)
}

fn make_dummy_params(
    tumble_amount: bitcoin::Amount,
    spend_transaction_fee_per_wu: bitcoin::Amount,
    tumbler_fee: bitcoin::Amount,
) -> Params {
    Params::new(
        random_p2wpkh(),
        random_p2wpkh(),
        0,
        tumble_amount,
        tumbler_fee,
        spend_transaction_fee_per_wu,
        bitcoin::Transaction {
            lock_time: 0,
            version: 2,
            input: Vec::new(),
            output: vec![],
        },
    )
}

struct BandwidthRecorder<T> {
    pub inner: T,
    pub bandwidth_used: usize,
}

impl<T> BandwidthRecorder<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            bandwidth_used: 0,
        }
    }
}

impl<T> FundTransaction for BandwidthRecorder<T>
where
    T: FundTransaction,
{
    fn fund_transaction(&self) -> anyhow::Result<bitcoin::Transaction> {
        FundTransaction::fund_transaction(&self.inner)
    }
}

impl<T> RedeemTransaction for BandwidthRecorder<T>
where
    T: RedeemTransaction,
{
    fn redeem_transaction(&self) -> anyhow::Result<bitcoin::Transaction> {
        self.inner.redeem_transaction()
    }
}

impl Transition<bitcoin::Transaction> for BandwidthRecorder<Sender> {
    fn transition(
        self,
        transaction: bitcoin::Transaction,
        rng: &mut impl Rng,
    ) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let inner = self.inner.transition(transaction, rng)?;

        Ok(Self {
            inner,
            bandwidth_used: self.bandwidth_used,
        })
    }
}

impl<T, M> NextMessage<M> for BandwidthRecorder<T>
where
    T: NextMessage<M>,
{
    fn next_message(&self, rng: &mut impl Rng) -> Result<M, NoMessage> {
        self.inner.next_message(rng)
    }
}

macro_rules! impl_transition_with_recording_size {
    ($inner: ty, $message: ty) => {
        impl Transition<$message> for BandwidthRecorder<$inner> {
            fn transition(self, message: $message, rng: &mut impl Rng) -> anyhow::Result<Self> {
                let bandwidth_used = add_message(self.bandwidth_used, &message);
                let inner = Transition::transition(self.inner, message, rng)?;

                Ok(Self {
                    inner,
                    bandwidth_used,
                })
            }
        }
    };
}

fn add_message<M>(mut total: usize, message: &M) -> usize
where
    M: Serialize,
{
    let bytes = serde_cbor::to_vec(&message).expect("message to be serializable");
    total += bytes.len();

    total
}

impl_transition_with_recording_size!(Sender, puzzle_promise::Message);
impl_transition_with_recording_size!(Sender, puzzle_solver::Message);
impl_transition_with_recording_size!(Receiver, puzzle_promise::Message);
impl_transition_with_recording_size!(Receiver, puzzle_solver::Message);
impl_transition_with_recording_size!(puzzle_promise::Tumbler, puzzle_promise::Message);
impl_transition_with_recording_size!(puzzle_solver::Tumbler, puzzle_solver::Message);