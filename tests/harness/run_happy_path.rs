use crate::harness::{MakeTransaction, NextMessage, Transition};
use a2l::{puzzle_promise, puzzle_solver};
use anyhow::Context;
use rand::Rng;

pub fn run_happy_path<TP, TS, S, R, B>(
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
        + MakeTransaction<puzzle_promise::FundTransaction>,
    TS: Transition<puzzle_solver::Message>
        + Transition<puzzle_solver::FundTransaction>
        + NextMessage<puzzle_solver::Message>
        + MakeTransaction<puzzle_solver::RedeemTransaction>,
    S: Transition<puzzle_promise::Message>
        + Transition<puzzle_solver::Message>
        + NextMessage<puzzle_solver::Message>
        + MakeTransaction<puzzle_solver::FundTransaction>
        + Transition<puzzle_solver::RedeemTransaction>,
    R: Transition<puzzle_promise::Message>
        + NextMessage<puzzle_promise::Message>
        + Transition<puzzle_solver::Message>
        + MakeTransaction<puzzle_promise::RedeemTransaction>,
    B: Transition<bitcoin::Transaction>,
{
    let ps_message0 = sender0.next_message()?;
    let tumbler_solver1 = tumbler_solver0.transition(ps_message0, rng)?;
    let ps_message1 = tumbler_solver1.next_message()?;
    let sender1 = sender0.transition(ps_message1, rng)?;

    let fund_transaction = sender1.make_transaction()?;
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

    let fund_transaction = tumbler_promise2.make_transaction()?;
    let blockchain = blockchain
        .transition(fund_transaction.into(), rng)
        .context("failed to broadcast tumbler's fund transaction")?;

    let ps_message4 = sender3.next_message()?;
    let tumbler_solver3 = tumbler_solver2.transition(ps_message4, rng)?;
    let ps_message5 = tumbler_solver3.next_message()?;
    let sender4 = sender3.transition(ps_message5, rng)?;
    let ps_message6 = sender4.next_message()?;
    let tumbler_solver4 = tumbler_solver3.transition(ps_message6, rng)?;

    let redeem_transaction = tumbler_solver4.make_transaction()?;
    let blockchain = blockchain
        .transition(redeem_transaction.clone().into(), rng)
        .context("failed to broadcast tumbler's redeem transaction")?;

    let sender5 = sender4.transition(redeem_transaction, rng)?;
    let ps_message7 = sender5.next_message()?;
    let receiver4 = receiver3.transition(ps_message7, rng)?;

    let redeem_transaction = receiver4.make_transaction()?;
    let blockchain = blockchain
        .transition(redeem_transaction.into(), rng)
        .context("failed to broadcast receiver's redeem transaction")?;

    Ok((
        tumbler_promise2,
        tumbler_solver4,
        sender5,
        receiver4,
        blockchain,
    ))
}
