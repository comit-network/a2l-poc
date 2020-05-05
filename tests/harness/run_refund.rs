use crate::harness::{FundTransaction, NextMessage, RefundTransaction, Transition};
use a2l_poc::{puzzle_promise, puzzle_solver};
use anyhow::Context;
use rand::Rng;

pub fn run_refund<TP, TS, S, R, B>(
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
        + FundTransaction
        + RefundTransaction,
    TS: Transition<puzzle_solver::Message> + NextMessage<puzzle_solver::Message>,
    S: Transition<puzzle_promise::Message>
        + Transition<puzzle_solver::Message>
        + NextMessage<puzzle_solver::Message>
        + FundTransaction
        + RefundTransaction
        + Transition<bitcoin::Transaction>,
    R: Transition<puzzle_promise::Message>
        + NextMessage<puzzle_promise::Message>
        + Transition<puzzle_solver::Message>,
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

    let refund_transaction = sender.refund_transaction()?;
    let blockchain = blockchain
        .transition(refund_transaction, rng)
        .context("failed to broadcast sender's refund transaction")?;

    let refund_transaction = tumbler_promise.refund_transaction()?;
    let blockchain = blockchain
        .transition(refund_transaction, rng)
        .context("failed to broadcast tumbler's refund transaction")?;

    Ok((
        tumbler_promise,
        tumbler_solver,
        sender,
        receiver,
        blockchain,
    ))
}
