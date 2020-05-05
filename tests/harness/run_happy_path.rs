use crate::harness::{FundTransaction, NextMessage, RedeemTransaction, Transition};
use a2l::{puzzle_promise, puzzle_solver};
use anyhow::Context;
use rand::Rng;

pub fn run_happy_path<TP, TS, S, R, B>(
    tumbler_promise: TP,
    tumbler_solver: TS,
    sender: S,
    receiver: R,
    blockchain: B,
    rng: &mut impl Rng,
) -> anyhow::Result<(TP, TS, S, R, B)>
where
    TP: Transition<puzzle_promise::Message>
        + NextMessage<puzzle_promise::Message>
        + FundTransaction,
    TS: Transition<puzzle_solver::Message>
        + NextMessage<puzzle_solver::Message>
        + RedeemTransaction,
    S: Transition<puzzle_promise::Message>
        + Transition<puzzle_solver::Message>
        + NextMessage<puzzle_solver::Message>
        + FundTransaction
        + Transition<bitcoin::Transaction>,
    R: Transition<puzzle_promise::Message>
        + NextMessage<puzzle_promise::Message>
        + Transition<puzzle_solver::Message>
        + RedeemTransaction,
    B: Transition<bitcoin::Transaction>,
{
    let message = tumbler_promise.next_message(rng)?;
    let receiver = receiver.transition(message, rng)?;
    let message = receiver.next_message(rng)?;
    let tumbler_promise = tumbler_promise.transition(message, rng)?;
    let message = tumbler_promise.next_message(rng)?;
    let receiver = receiver.transition(message, rng)?;
    let message = receiver.next_message(rng)?;
    let sender = sender.transition(message, rng)?;

    let fund_transaction = tumbler_promise.fund_transaction()?;
    let blockchain = blockchain
        .transition(fund_transaction, rng)
        .context("failed to broadcast tumbler's fund transaction")?;

    let message = tumbler_solver.next_message(rng)?;
    let sender = sender.transition(message, rng)?;
    let message = sender.next_message(rng)?;
    let tumbler_solver = tumbler_solver.transition(message, rng)?;
    let message = tumbler_solver.next_message(rng)?;
    let sender = sender.transition(message, rng)?;
    let message = sender.next_message(rng)?;
    let tumbler_solver = tumbler_solver.transition(message, rng)?;

    let fund_transaction = sender.fund_transaction()?;
    let blockchain = blockchain
        .transition(fund_transaction, rng)
        .context("failed to broadcast sender's fund transaction")?;

    let redeem_transaction = tumbler_solver.redeem_transaction()?;
    let blockchain = blockchain
        .transition(redeem_transaction.clone(), rng)
        .context("failed to broadcast tumbler's redeem transaction")?;

    let sender = sender.transition(redeem_transaction, rng)?;
    let message = NextMessage::<puzzle_solver::Message>::next_message(&sender, rng)?;
    let receiver = receiver.transition(message, rng)?;

    let redeem_transaction = receiver.redeem_transaction()?;
    let blockchain = blockchain
        .transition(redeem_transaction, rng)
        .context("failed to broadcast receiver's redeem transaction")?;

    Ok((
        tumbler_promise,
        tumbler_solver,
        sender,
        receiver,
        blockchain,
    ))
}
