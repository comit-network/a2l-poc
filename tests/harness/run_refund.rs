use crate::harness::{MakeTransaction, NextMessage, Transition};
use a2l::{puzzle_promise, puzzle_solver};
use anyhow::Context;
use rand::Rng;

pub fn run_refund<TP, TS, S, R, B>(
    tumbler_promise0: TP,
    tumbler_solver0: TS,
    sender0: S,
    receiver0: R,
    blockchain: B,
    rng: &mut impl Rng,
) -> anyhow::Result<(TP, TS, S, R, B)>
where
    TP: Transition<puzzle_promise::Message>
        + NextMessage<puzzle_promise::Message>
        + MakeTransaction<puzzle_promise::FundTransaction>
        + MakeTransaction<puzzle_promise::RefundTransaction>,
    TS: Transition<puzzle_solver::Message>
        + NextMessage<puzzle_solver::Message>
        + Transition<puzzle_solver::FundTransaction>,
    S: Transition<puzzle_promise::Message>
        + Transition<puzzle_solver::Message>
        + NextMessage<puzzle_solver::Message>
        + MakeTransaction<puzzle_solver::FundTransaction>
        + MakeTransaction<puzzle_solver::RefundTransaction>,
    R: Transition<puzzle_promise::Message>
        + NextMessage<puzzle_promise::Message>
        + Transition<puzzle_solver::Message>,
    B: Transition<bitcoin::Transaction>,
{
    let ps_message0 = sender0.next_message()?;
    let tumbler_solver1 = tumbler_solver0.transition(ps_message0, rng)?;
    let ps_message1 = tumbler_solver1.next_message()?;
    let sender1 = sender0.transition(ps_message1, rng)?;

    let fund_transaction: puzzle_solver::FundTransaction = sender1.make_transaction()?;
    let blockchain = blockchain
        .transition(fund_transaction.clone().into(), rng)
        .context("failed to broadcast sender's fund transaction")?;

    let tumbler_solver2 = tumbler_solver1.transition(fund_transaction, rng)?;
    let ps_message2 = tumbler_solver2.next_message()?;
    let sender2 = sender1.transition(ps_message2, rng)?;

    let ps_message3 = sender2.next_message()?;
    let receiver1 = receiver0.transition(ps_message3, rng)?;

    let pp_message0 = receiver1.next_message()?;
    let tumbler_promise1 = tumbler_promise0.transition(pp_message0, rng)?;
    let pp_message1 = tumbler_promise1.next_message()?;
    let receiver2 = receiver1.transition(pp_message1, rng)?;
    let pp_message2 = receiver2.next_message()?;
    let tumbler_promise2 = tumbler_promise1.transition(pp_message2, rng)?;
    let pp_message3 = tumbler_promise2.next_message()?;
    let receiver3 = receiver2.transition(pp_message3, rng)?;
    let pp_message4 = receiver3.next_message()?;

    let sender3 = sender2.transition(pp_message4, rng)?;

    let fund_transaction: puzzle_promise::FundTransaction = tumbler_promise2.make_transaction()?;
    let blockchain = blockchain
        .transition(fund_transaction.into(), rng)
        .context("failed to broadcast tumbler's fund transaction")?;

    let refund_transaction: puzzle_promise::RefundTransaction =
        tumbler_promise2.make_transaction()?;
    let blockchain = blockchain
        .transition(refund_transaction.into(), rng)
        .context("failed to broadcast tumbler's refund transaction")?;

    let refund_transaction: puzzle_solver::RefundTransaction = sender3.make_transaction()?;
    let blockchain = blockchain
        .transition(refund_transaction.into(), rng)
        .context("failed to broadcast sender's refund transaction")?;

    Ok((
        tumbler_promise2,
        tumbler_solver2,
        sender3,
        receiver3,
        blockchain,
    ))
}
