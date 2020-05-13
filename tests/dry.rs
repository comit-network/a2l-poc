pub mod harness;

use crate::harness::{
    random_p2wpkh, run_happy_path, run_refund, MakeTransaction, NextMessage, Transition,
};
use a2l::{
    hsm_cl, pointcheval_sanders, puzzle_promise, puzzle_solver,
    receiver::{self, Receiver},
    sender::{self, Sender},
    Params,
};
use anyhow::bail;
use indicatif::ProgressIterator;
use itertools::Itertools;
use rand::{thread_rng, Rng};
use serde::Serialize;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

#[test]
fn dry_happy_path() {
    let (blockchain, tumbler_promise, tumbler_solver, sender, receiver) = make_actors::<NullStrategy>(
        bitcoin::Amount::from_sat(10_000_000),
        bitcoin::Amount::from_sat(10),
        bitcoin::Amount::from_sat(10_000),
    );

    let res = run_happy_path(
        tumbler_promise,
        tumbler_solver,
        sender,
        receiver,
        blockchain,
        &mut thread_rng(),
    );

    res.unwrap();
}

#[test]
fn dry_refund() {
    let (blockchain, tumbler_promise, tumbler_solver, sender, receiver) = make_actors::<NullStrategy>(
        bitcoin::Amount::from_sat(10_000_000),
        bitcoin::Amount::from_sat(10),
        bitcoin::Amount::from_sat(10_000),
    );

    let res = run_refund(
        tumbler_promise,
        tumbler_solver,
        sender,
        receiver,
        blockchain,
        &mut thread_rng(),
    );

    res.unwrap();
}

#[test]
fn happy_path_fees() -> anyhow::Result<()> {
    let tumble_amount = bitcoin::Amount::from_sat(10_000_000);
    let spend_transaction_fee_per_wu = bitcoin::Amount::from_sat(10);
    let tumbler_fee = bitcoin::Amount::from_sat(10_000);
    let (blockchain, tumbler_promise, tumbler_solver, sender, receiver) =
        make_actors::<NullStrategy>(tumble_amount, spend_transaction_fee_per_wu, tumbler_fee);

    let (_, _, _, _, blockchain) = run_happy_path(
        tumbler_promise,
        tumbler_solver,
        sender,
        receiver,
        blockchain,
        &mut thread_rng(),
    )?;

    let (sender_fund, tumbler_fund, tumbler_redeem, receiver_redeem) = match blockchain.0.as_slice()
    {
        [sender_fund, tumbler_fund, tumbler_redeem, receiver_redeem] => {
            (sender_fund, tumbler_fund, tumbler_redeem, receiver_redeem)
        }
        _ => bail!("wrong transactions in blockchain"),
    };
    assert_eq!(
        bitcoin::Amount::from_sat(sender_fund.output[0].value),
        tumble_amount + tumbler_fee + a2l::spend_tx_miner_fee(spend_transaction_fee_per_wu)
    );
    assert_eq!(
        bitcoin::Amount::from_sat(tumbler_redeem.output[0].value),
        tumble_amount + tumbler_fee
    );
    assert_eq!(
        bitcoin::Amount::from_sat(tumbler_fund.output[0].value),
        tumble_amount + a2l::spend_tx_miner_fee(spend_transaction_fee_per_wu)
    );
    assert_eq!(
        bitcoin::Amount::from_sat(receiver_redeem.output[0].value),
        tumble_amount
    );

    Ok(())
}

#[test]
fn redeem_transaction_size() -> anyhow::Result<()> {
    let (blockchain, tumbler_promise, tumbler_solver, sender, receiver) = make_actors::<NullStrategy>(
        bitcoin::Amount::from_sat(10_000_000),
        bitcoin::Amount::from_sat(10),
        bitcoin::Amount::from_sat(10_000),
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

    println!(
        "Total weight of both redeem transactions is {} and does not exceed maximum expected weight of {}.",
        redeem_tx_weight, max_expected_weight
    );

    Ok(())
}

#[test]
fn protocol_bandwidth() -> anyhow::Result<()> {
    let (blockchain, tumbler_promise, tumbler_solver, sender, receiver) =
        make_actors::<BandwidthRecordingStrategy>(
            bitcoin::Amount::from_sat(10_000_000),
            bitcoin::Amount::from_sat(10),
            bitcoin::Amount::from_sat(10_000),
        );

    let (tumbler_promise, tumbler_solver, sender, receiver, _) = run_happy_path(
        tumbler_promise,
        tumbler_solver,
        sender,
        receiver,
        blockchain,
        &mut thread_rng(),
    )?;

    let total_bandwidth = tumbler_promise.strategy.bandwidth_used
        + tumbler_solver.strategy.bandwidth_used
        + sender.strategy.bandwidth_used
        + receiver.strategy.bandwidth_used;
    let max_expected_bandwidth = 8000;

    assert!(
        max_expected_bandwidth >= total_bandwidth,
        "{} >= {}",
        max_expected_bandwidth,
        total_bandwidth
    );

    println!(
        "Total bandwidth using CBOR encoding is {} bytes and does not exceed maximum expected bandwidth of {} bytes.",
        total_bandwidth, max_expected_bandwidth
    );

    Ok(())
}

#[test]
fn protocol_computation_time() -> anyhow::Result<()> {
    let mut per_message_computation_times = HashMap::<String, Vec<Duration>>::new();
    let mut full_protocol_computation_times = Vec::<Duration>::new();

    let (blockchain, tumbler_promise, tumbler_solver, sender, receiver) =
        make_actors::<TimeRecordingStrategy>(
            bitcoin::Amount::from_sat(10_000_000),
            bitcoin::Amount::from_sat(10),
            bitcoin::Amount::from_sat(10_000),
        );

    for _ in (0..50).progress() {
        let (tumbler_promise, tumbler_solver, sender, receiver, _) = run_happy_path(
            tumbler_promise.clone(),
            tumbler_solver.clone(),
            sender.clone(),
            receiver.clone(),
            blockchain.clone(),
            &mut thread_rng(),
        )?;

        let mut computation_time = tumbler_promise.strategy.computation_time;
        computation_time.extend(tumbler_solver.strategy.computation_time);
        computation_time.extend(sender.strategy.computation_time);
        computation_time.extend(receiver.strategy.computation_time);

        for (key, value) in computation_time.iter() {
            per_message_computation_times
                .entry(key.to_owned())
                .or_default()
                .push(*value)
        }

        full_protocol_computation_times.push(computation_time.values().sum());
    }

    let mut full_protocol_variances = Vec::<Duration>::new();

    println!("| Receiving message                |     Mean | Standard deviation |");
    println!("| ---------------------------------|----------|------------------- |");
    for (key, value) in
        per_message_computation_times
            .into_iter()
            .sorted_by_key(|(key, _)| match key.as_ref() {
                "puzzle_solver::Message0" => 0,
                "puzzle_solver::Message1" => 1,
                "puzzle_solver::FundTransaction" => 2,
                "puzzle_solver::Message2" => 3,
                "puzzle_solver::Message3" => 4,
                "puzzle_promise::Message0" => 5,
                "puzzle_promise::Message1" => 6,
                "puzzle_promise::Message2" => 7,
                "puzzle_promise::Message3" => 8,
                "puzzle_promise::Message4" => 9,
                "puzzle_solver::Message4" => 10,
                "puzzle_solver::Message5" => 11,
                "puzzle_solver::Message6" => 12,
                "puzzle_solver::RedeemTransaction" => 13,
                "puzzle_solver::Message7" => 14,
                message => panic!("unexpected message {}", message),
            })
    {
        let mean = stats::mean(value.iter().map(|duration| duration.as_micros()));
        let variance = stats::variance(value.iter().map(|duration| duration.as_micros()));

        println!(
            "| {:32} | {:>8} | {:>18} |",
            key,
            format!("{:.2?}", Duration::from_micros((mean) as u64)),
            format!("{:.2?}", Duration::from_micros((variance.sqrt()) as u64))
        );

        full_protocol_variances.push(Duration::from_micros(variance as u64))
    }

    println!(
        "| Full protocol                    | {:>8} | {:>18} |",
        format!(
            "{:.2?}",
            Duration::from_micros(stats::mean(
                full_protocol_computation_times
                    .iter()
                    .map(|duration| duration.as_micros())
            ) as u64)
        ),
        format!(
            "{:.2?}",
            Duration::from_micros(
                (full_protocol_variances.iter().sum::<Duration>().as_micros() as f64).sqrt() as u64
            )
        )
    );

    Ok(())
}

#[derive(Default, Debug, Clone)]
struct Blockchain(Vec<bitcoin::Transaction>);

impl<T> Transition<T> for Blockchain
where
    T: Into<bitcoin::Transaction>,
{
    fn transition(self, transaction: T, _: &mut impl rand::Rng) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let mut vec = self.0;
        vec.push(transaction.into());
        Ok(Blockchain(vec))
    }
}

#[allow(clippy::type_complexity)]
fn make_actors<S: Default>(
    tumble_amount: bitcoin::Amount,
    spend_transaction_fee_per_wu: bitcoin::Amount,
    tumbler_fee: bitcoin::Amount,
) -> (
    Blockchain,
    Actor<puzzle_promise::Tumbler, S>,
    Actor<puzzle_solver::Tumbler, S>,
    Actor<Sender, S>,
    Actor<Receiver, S>,
) {
    let he_keypair = hsm_cl::keygen();
    let ps_keypair = pointcheval_sanders::keygen(&mut thread_rng());

    let blockchain = Blockchain::default();

    let (tumbler_promise, receiver) = make_puzzle_promise_actors(
        tumble_amount,
        spend_transaction_fee_per_wu,
        he_keypair.clone(),
        he_keypair.to_pk(),
        ps_keypair.clone(),
    );

    let (tumbler_solver, sender) = make_puzzle_solver_actors(
        tumble_amount,
        spend_transaction_fee_per_wu,
        tumbler_fee,
        he_keypair,
        ps_keypair.clone(),
        ps_keypair.public_key,
    );

    (
        blockchain,
        Actor::new(tumbler_promise),
        Actor::new(tumbler_solver),
        Actor::new(sender),
        Actor::new(receiver),
    )
}

fn make_puzzle_promise_actors(
    tumble_amount: bitcoin::Amount,
    spend_transaction_fee_per_wu: bitcoin::Amount,
    he_keypair: hsm_cl::KeyPair,
    he_publickey: hsm_cl::PublicKey,
    ps_keypair: pointcheval_sanders::KeyPair,
) -> (puzzle_promise::Tumbler, Receiver) {
    let params = make_dummy_params(
        tumble_amount,
        spend_transaction_fee_per_wu,
        bitcoin::Amount::from_sat(0),
    );

    let tumbler =
        puzzle_promise::Tumbler::new(params.clone(), he_keypair, ps_keypair, &mut thread_rng());
    let receiver = receiver::Receiver::new(params, &mut thread_rng(), he_publickey);

    (tumbler, receiver)
}

fn make_puzzle_solver_actors(
    tumble_amount: bitcoin::Amount,
    spend_transaction_fee_per_wu: bitcoin::Amount,
    tumbler_fee: bitcoin::Amount,
    he_keypair: hsm_cl::KeyPair,
    ps_keypair: pointcheval_sanders::KeyPair,
    ps_publickey: pointcheval_sanders::PublicKey,
) -> (puzzle_solver::Tumbler, Sender) {
    let params = make_dummy_params(tumble_amount, spend_transaction_fee_per_wu, tumbler_fee);

    let tumbler =
        puzzle_solver::Tumbler::new(params.clone(), he_keypair, ps_keypair, &mut thread_rng());
    let sender = sender::Sender::new(params, ps_publickey, &mut thread_rng());

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

#[derive(Clone)]
struct Actor<T, S> {
    pub inner: T,
    pub strategy: S,
}

#[derive(Default, Clone)]
struct BandwidthRecordingStrategy {
    pub bandwidth_used: usize,
}

#[derive(Default, Clone)]
struct TimeRecordingStrategy {
    pub computation_time: HashMap<String, Duration>,
}

#[derive(Default, Clone)]
struct NullStrategy;

impl<T, S> Actor<T, S>
where
    S: Default,
{
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            strategy: S::default(),
        }
    }
}

trait ForwardTransition {}
impl ForwardTransition for NullStrategy {}

trait BandwidthRelevant {}
impl BandwidthRelevant for puzzle_promise::Message {}
impl BandwidthRelevant for puzzle_solver::Message {}

impl<T, S, TX> MakeTransaction<TX> for Actor<T, S>
where
    T: MakeTransaction<TX>,
{
    fn make_transaction(&self) -> anyhow::Result<TX> {
        self.inner.make_transaction()
    }
}

impl<T, M, S> NextMessage<M> for Actor<T, S>
where
    T: NextMessage<M>,
{
    fn next_message(&self) -> anyhow::Result<M> {
        self.inner.next_message()
    }
}

impl<M, T> Transition<M> for Actor<T, BandwidthRecordingStrategy>
where
    M: BandwidthRelevant + Serialize,
    T: Transition<M>,
{
    fn transition(self, message: M, rng: &mut impl Rng) -> anyhow::Result<Self> {
        let bandwidth_used = {
            let bytes = serde_cbor::to_vec(&message).expect("message to be serializable");
            self.strategy.bandwidth_used + bytes.len()
        };
        let inner = Transition::transition(self.inner, message, rng)?;

        Ok(Self {
            inner,
            strategy: BandwidthRecordingStrategy { bandwidth_used },
        })
    }
}

impl Transition<puzzle_solver::RedeemTransaction> for Actor<Sender, BandwidthRecordingStrategy> {
    fn transition(
        self,
        transaction: puzzle_solver::RedeemTransaction,
        rng: &mut impl Rng,
    ) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let inner = self.inner.transition(transaction, rng)?;

        Ok(Self {
            inner,
            strategy: self.strategy,
        })
    }
}

impl Transition<puzzle_solver::FundTransaction>
    for Actor<puzzle_solver::Tumbler, BandwidthRecordingStrategy>
{
    fn transition(
        self,
        transaction: puzzle_solver::FundTransaction,
        rng: &mut impl Rng,
    ) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let inner = self.inner.transition(transaction, rng)?;

        Ok(Self {
            inner,
            strategy: self.strategy,
        })
    }
}

impl<M, T> Transition<M> for Actor<T, TimeRecordingStrategy>
where
    T: Transition<M>,
    M: TransitionName,
{
    fn transition(mut self, message: M, rng: &mut impl Rng) -> anyhow::Result<Self> {
        let transition_name = message.transition_name();

        let now = Instant::now();
        let inner = Transition::transition(self.inner, message, rng)?;
        let time_elapsed = now.elapsed();
        self.strategy
            .computation_time
            .insert(transition_name, time_elapsed);

        Ok(Self {
            inner,
            strategy: self.strategy,
        })
    }
}

trait TransitionName {
    fn transition_name(&self) -> String;
}

impl TransitionName for puzzle_promise::Message {
    fn transition_name(&self) -> String {
        match self {
            puzzle_promise::Message::Message0(_) => String::from("puzzle_promise::Message0"),
            puzzle_promise::Message::Message1(_) => String::from("puzzle_promise::Message1"),
            puzzle_promise::Message::Message2(_) => String::from("puzzle_promise::Message2"),
            puzzle_promise::Message::Message3(_) => String::from("puzzle_promise::Message3"),
            puzzle_promise::Message::Message4(_) => String::from("puzzle_promise::Message4"),
        }
    }
}

impl TransitionName for puzzle_solver::Message {
    fn transition_name(&self) -> String {
        match self {
            puzzle_solver::Message::Message0(_) => String::from("puzzle_solver::Message0"),
            puzzle_solver::Message::Message1(_) => String::from("puzzle_solver::Message1"),
            puzzle_solver::Message::Message2(_) => String::from("puzzle_solver::Message2"),
            puzzle_solver::Message::Message3(_) => String::from("puzzle_solver::Message3"),
            puzzle_solver::Message::Message4(_) => String::from("puzzle_solver::Message4"),
            puzzle_solver::Message::Message5(_) => String::from("puzzle_solver::Message5"),
            puzzle_solver::Message::Message6(_) => String::from("puzzle_solver::Message6"),
            puzzle_solver::Message::Message7(_) => String::from("puzzle_solver::Message7"),
        }
    }
}

impl TransitionName for puzzle_solver::RedeemTransaction {
    fn transition_name(&self) -> String {
        String::from("puzzle_solver::RedeemTransaction")
    }
}

impl TransitionName for puzzle_solver::FundTransaction {
    fn transition_name(&self) -> String {
        String::from("puzzle_solver::FundTransaction")
    }
}

impl<M, T, S> Transition<M> for Actor<T, S>
where
    S: ForwardTransition,
    T: Transition<M>,
{
    fn transition(self, message: M, rng: &mut impl Rng) -> anyhow::Result<Self> {
        let inner = Transition::transition(self.inner, message, rng)?;

        Ok(Self {
            inner,
            strategy: self.strategy,
        })
    }
}
