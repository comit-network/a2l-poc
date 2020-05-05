pub mod harness;

use crate::harness::{FundTransaction, RedeemTransaction, RefundTransaction, Transition};
use a2l::{hsm_cl, puzzle_promise, puzzle_solver, receiver, sender, NoMessage, Params};
use anyhow::Context;
use bitcoin::{
    consensus::deserialize, consensus::encode::serialize_hex, hashes::hex::FromHex, Transaction,
};
use harness::{run_happy_path, run_refund};
use rand::{thread_rng, Rng};
use serde::*;
use testcontainers::{clients, images::coblox_bitcoincore::BitcoinCore, Container, Docker};
use ureq::SerdeValue;

#[test]
fn e2e_happy_path() -> anyhow::Result<()> {
    // global A2L parameters
    let he_keypair = hsm_cl::keygen(b"A2L-PoC");

    // parameters for this instance of a2l
    let tumble_amount = bitcoin::Amount::from_sat(10_000_000);
    let spend_transaction_fee_per_wu = bitcoin::Amount::from_sat(10);
    let tumbler_fee = bitcoin::Amount::from_sat(10_000);

    let client = clients::Cli::default();

    let blockchain = BitcoindBlockchain::new(&client)?;
    let (tumbler_promise, receiver) = make_puzzle_promise_actors(
        &blockchain.bitcoind_url,
        tumble_amount,
        spend_transaction_fee_per_wu,
        he_keypair.clone(),
        he_keypair.to_pk(),
    )?;
    let (tumbler_solver, sender) = make_puzzle_solver_actors(
        &blockchain.bitcoind_url,
        tumble_amount,
        spend_transaction_fee_per_wu,
        tumbler_fee,
        he_keypair,
    )?;

    let (tumbler_promise, tumbler_solver, sender, receiver, _) = run_happy_path(
        tumbler_promise,
        tumbler_solver,
        sender,
        receiver,
        blockchain,
        &mut thread_rng(),
    )?;

    assert_eq!(
        receiver.current_balance()?,
        receiver.expected_balance_after_tumble()
    );
    assert_eq!(
        tumbler_promise.current_balance()?,
        tumbler_promise.expected_balance_after_tumble()
    );
    assert_eq!(
        tumbler_solver.current_balance()?,
        tumbler_solver.expected_balance_after_tumble()
    );
    assert_eq!(
        sender.current_balance()?,
        sender.expected_balance_after_tumble()
    );
    let tumbler_promise_diff =
        tumbler_promise.starting_balance - tumbler_promise.current_balance()?; // we expect the wallet for tumbler_promise to have less money after the tumble
    let tumbler_solver_diff = tumbler_solver.current_balance()? - tumbler_solver.starting_balance; // we expect the wallet for tumbler_solver to have more money after the tumble

    assert!(
        tumbler_solver_diff > tumbler_promise_diff,
        "Tumbler should make money: solver_wallet_diff({}) > promise_wallet_diff({})",
        tumbler_solver_diff,
        tumbler_promise_diff
    );

    Ok(())
}

#[test]
fn e2e_refund() -> anyhow::Result<()> {
    // global A2L parameters
    let he_keypair = hsm_cl::keygen(b"A2L-PoC");

    // parameters for this instance of a2l
    let tumble_amount = bitcoin::Amount::from_sat(10_000_000);
    let spend_transaction_fee_per_wu = bitcoin::Amount::from_sat(10);
    let tumbler_fee = bitcoin::Amount::from_sat(10_000);

    let client = clients::Cli::default();

    let blockchain = BitcoindBlockchain::new(&client)?;
    let (tumbler_promise, receiver) = make_puzzle_promise_actors(
        &blockchain.bitcoind_url,
        tumble_amount,
        spend_transaction_fee_per_wu,
        he_keypair.clone(),
        he_keypair.to_pk(),
    )?;
    let (tumbler_solver, sender) = make_puzzle_solver_actors(
        &blockchain.bitcoind_url,
        tumble_amount,
        spend_transaction_fee_per_wu,
        tumbler_fee,
        he_keypair,
    )?;

    let (tumbler_promise, tumbler_solver, sender, receiver, _) = run_refund(
        tumbler_promise,
        tumbler_solver,
        sender,
        receiver,
        blockchain,
        &mut thread_rng(),
    )?;

    assert_eq!(
        receiver.current_balance()?,
        receiver.expected_balance_after_no_tumble()
    );
    assert_eq!(
        tumbler_promise.current_balance()?,
        tumbler_promise.expected_balance_after_no_tumble()
    );
    assert_eq!(
        tumbler_solver.current_balance()?,
        tumbler_solver.expected_balance_after_no_tumble()
    );
    assert_eq!(
        sender.current_balance()?,
        sender.expected_balance_after_no_tumble()
    );

    Ok(())
}

struct E2ESender {
    inner: sender::Sender,
    wallet: Wallet,
    starting_balance: bitcoin::Amount,
    fund_fee: bitcoin::Amount,
    tumbler_fee: bitcoin::Amount,
    tumble_amount: bitcoin::Amount,
    spend_tx_miner_fee: bitcoin::Amount,
}

impl E2ESender {
    fn current_balance(&self) -> anyhow::Result<bitcoin::Amount> {
        self.wallet.get_balance()
    }

    fn expected_balance_after_tumble(&self) -> bitcoin::Amount {
        self.starting_balance
            - self.fund_fee // we pay the miner for the fund transaction
            - self.tumble_amount // we pay the tumble amount
            - self.spend_tx_miner_fee // we pay the miner for the redeem transaction
            - self.tumbler_fee // we pay the tumbler for doing the protocol
    }

    fn expected_balance_after_no_tumble(&self) -> bitcoin::Amount {
        self.starting_balance
            - self.fund_fee // we pay the miner for the fund transaction, regardless of the outcome
            - self.spend_tx_miner_fee // we pay the miner for the refund transaction, regardless of the outcome
    }
}

impl FundTransaction for E2ESender {
    fn fund_transaction(&self) -> anyhow::Result<bitcoin::Transaction> {
        let unsigned_fund_transaction = self.inner.fund_transaction()?;
        let signed_transaction = self
            .wallet
            .sign(&unsigned_fund_transaction)
            .context("failed to sign sender fund transaction")?;

        Ok(signed_transaction)
    }
}

impl RefundTransaction for E2ESender {
    fn refund_transaction(&self) -> anyhow::Result<Transaction> {
        let transaction = self.inner.refund_transaction()?;

        Ok(transaction)
    }
}

forward_transition_to_inner!(E2ESender, sender::Sender);
forward_next_message_to_inner!(E2ESender, sender::Sender);

struct E2ETumblerPromise {
    inner: puzzle_promise::Tumbler,
    wallet: Wallet,
    starting_balance: bitcoin::Amount,
    fund_fee: bitcoin::Amount,
    tumble_amount: bitcoin::Amount,
    spend_tx_miner_fee: bitcoin::Amount,
}

impl E2ETumblerPromise {
    fn current_balance(&self) -> anyhow::Result<bitcoin::Amount> {
        self.wallet.get_balance()
    }

    fn expected_balance_after_tumble(&self) -> bitcoin::Amount {
        self.starting_balance
            - self.fund_fee // we pay the miner for the fund transaction
            - self.tumble_amount // we pay the tumble amount
            - self.spend_tx_miner_fee // we pay the miner for the redeem transaction
    }

    fn expected_balance_after_no_tumble(&self) -> bitcoin::Amount {
        self.starting_balance
            - self.fund_fee // we pay the miner for the fund transaction, regardless of the outcome
            - self.spend_tx_miner_fee // we pay the miner for the refund transaction, regardless of the outcome
    }
}

impl FundTransaction for E2ETumblerPromise {
    fn fund_transaction(&self) -> anyhow::Result<bitcoin::Transaction> {
        let unsigned_fund_transaction = self.inner.fund_transaction()?;
        let signed_transaction = self
            .wallet
            .sign(&unsigned_fund_transaction)
            .context("failed to sign tumbler fund transaction")?;

        Ok(signed_transaction)
    }
}

impl RefundTransaction for E2ETumblerPromise {
    fn refund_transaction(&self) -> anyhow::Result<Transaction> {
        self.inner.refund_transaction()
    }
}

forward_transition_to_inner!(E2ETumblerPromise, puzzle_promise::Tumbler);
forward_next_message_to_inner!(E2ETumblerPromise, puzzle_promise::Tumbler);

struct E2ETumblerSolver {
    inner: puzzle_solver::Tumbler,
    wallet: Wallet,
    tumble_amount: bitcoin::Amount,
    tumbler_fee: bitcoin::Amount,
    starting_balance: bitcoin::Amount,
}

impl E2ETumblerSolver {
    fn current_balance(&self) -> anyhow::Result<bitcoin::Amount> {
        self.wallet.get_balance()
    }

    fn expected_balance_after_tumble(&self) -> bitcoin::Amount {
        self.starting_balance
            + self.tumble_amount // we receive the tumble amount
            + self.tumbler_fee // we are being paid 🎉
    }

    fn expected_balance_after_no_tumble(&self) -> bitcoin::Amount {
        self.starting_balance // no changes to our balance if refund happens
    }
}

impl RedeemTransaction for E2ETumblerSolver {
    fn redeem_transaction(&self) -> anyhow::Result<bitcoin::Transaction> {
        self.inner.redeem_transaction()
    }
}

forward_transition_to_inner!(E2ETumblerSolver, puzzle_solver::Tumbler);
forward_next_message_to_inner!(E2ETumblerSolver, puzzle_solver::Tumbler);

struct E2EReceiver {
    inner: receiver::Receiver,
    wallet: Wallet,
    starting_balance: bitcoin::Amount,
    tumble_amount: bitcoin::Amount,
}

impl E2EReceiver {
    fn current_balance(&self) -> anyhow::Result<bitcoin::Amount> {
        self.wallet.get_balance()
    }

    fn expected_balance_after_tumble(&self) -> bitcoin::Amount {
        self.starting_balance + self.tumble_amount // we receive the tumble amount
    }

    fn expected_balance_after_no_tumble(&self) -> bitcoin::Amount {
        self.starting_balance // no changes to our balance if refund happens
    }
}

impl RedeemTransaction for E2EReceiver {
    fn redeem_transaction(&self) -> anyhow::Result<bitcoin::Transaction> {
        self.inner.redeem_transaction()
    }
}

forward_transition_to_inner!(E2EReceiver, receiver::Receiver);
forward_next_message_to_inner!(E2EReceiver, receiver::Receiver);

struct BitcoindBlockchain<'c> {
    _container: Container<'c, clients::Cli, BitcoinCore>,
    bitcoind_url: String,
}

impl<'c> BitcoindBlockchain<'c> {
    pub fn new(client: &'c clients::Cli) -> anyhow::Result<Self> {
        let container = client.run(BitcoinCore::default().with_tag("0.19.1"));
        let port = container.get_host_port(18443);

        let auth = container.image().auth();
        let url = format!(
            "http://{}:{}@localhost:{}",
            &auth.username,
            &auth.password,
            port.unwrap()
        );

        let address = rpc_command::<String>(
            &url,
            ureq::json!({"jsonrpc": "1.0", "method": "getnewaddress", "params": ["", "bech32"] }),
        )?;
        let _ = rpc_command::<Vec<String>>(
            &url,
            ureq::json!({"jsonrpc": "1.0", "method": "generatetoaddress", "params": [101, address] }),
        )?;

        Ok(Self {
            _container: container,
            bitcoind_url: url,
        })
    }
}

impl Transition<bitcoin::Transaction> for BitcoindBlockchain<'_> {
    fn transition(self, message: Transaction, _: &mut impl Rng) -> anyhow::Result<Self> {
        let hex = &serialize_hex(&message);

        rpc_command::<SerdeValue>(
            &self.bitcoind_url,
            ureq::json!({"jsonrpc": "1.0", "method": "sendrawtransaction", "params": [ hex ] }),
        )
        .context("bitcoind refused to broadcast raw transaction")?;

        mine(&format!("{}/wallet/", &self.bitcoind_url))?;

        Ok(self)
    }
}

fn make_puzzle_promise_actors(
    bitcoind_url: &str,
    tumble_amount: bitcoin::Amount,
    spend_transaction_fee_per_wu: bitcoin::Amount,
    he_keypair: hsm_cl::KeyPair,
    he_publickey: hsm_cl::PublicKey,
) -> anyhow::Result<(E2ETumblerPromise, E2EReceiver)> {
    let tumbler_wallet = Wallet::new(
        bitcoind_url.to_owned(),
        String::from("tumbler_promise"),
        Some(10),
    )?;
    let receiver_wallet = Wallet::new(bitcoind_url.to_owned(), String::from("receiver"), None)?;

    let refund_address = tumbler_wallet.getnewaddress()?;
    let redeem_address = receiver_wallet.getnewaddress()?;

    let spend_tx_miner_fee = a2l::spend_tx_miner_fee(spend_transaction_fee_per_wu);

    let PartialFundTransaction {
        inner: partial_fund_transaction,
        expected_fee: fund_fee,
    } = tumbler_wallet
        .make_partial_fund_transaction(tumble_amount + spend_tx_miner_fee)
        .context("failed to make tumbler fund transaction")?;

    let params = Params::new(
        redeem_address.parse()?,
        refund_address.parse()?,
        0,
        tumble_amount,
        bitcoin::Amount::from_sat(0), // TODO: make different params for the individual protocols, we don't even want to pass this here
        spend_transaction_fee_per_wu,
        partial_fund_transaction,
    );

    let tumbler = puzzle_promise::Tumbler::new(params.clone(), he_keypair, &mut thread_rng());
    let receiver = receiver::Receiver::new(params, &mut thread_rng(), he_publickey);

    let tumbler_starting_balance = tumbler_wallet.get_balance()?;
    let tumbler = E2ETumblerPromise {
        inner: tumbler,
        wallet: tumbler_wallet,
        starting_balance: tumbler_starting_balance,
        fund_fee,
        tumble_amount,
        spend_tx_miner_fee,
    };
    let receiver_starting_balance = receiver_wallet.get_balance()?;
    let receiver = E2EReceiver {
        inner: receiver,
        wallet: receiver_wallet,
        starting_balance: receiver_starting_balance,
        tumble_amount,
    };

    Ok((tumbler, receiver))
}

fn make_puzzle_solver_actors(
    bitcoind_url: &str,
    tumble_amount: bitcoin::Amount,
    spend_transaction_fee_per_wu: bitcoin::Amount,
    tumbler_fee: bitcoin::Amount,
    he_keypair: hsm_cl::KeyPair,
) -> anyhow::Result<(E2ETumblerSolver, E2ESender)> {
    let tumbler_wallet = Wallet::new(
        bitcoind_url.to_owned(),
        String::from("tumbler_solver"),
        None,
    )?;
    let sender_wallet = Wallet::new(bitcoind_url.to_owned(), String::from("sender"), Some(10))?;

    let refund_address = sender_wallet.getnewaddress()?;
    let redeem_address = tumbler_wallet.getnewaddress()?;

    let spend_tx_miner_fee = a2l::spend_tx_miner_fee(spend_transaction_fee_per_wu);

    let PartialFundTransaction {
        inner: partial_fund_transaction,
        expected_fee: fund_fee,
    } = sender_wallet
        .make_partial_fund_transaction(tumble_amount + tumbler_fee + spend_tx_miner_fee)
        .context("failed to make sender fund transaction")?;

    let params = Params::new(
        redeem_address.parse()?,
        refund_address.parse()?,
        0,
        tumble_amount,
        tumbler_fee,
        spend_transaction_fee_per_wu,
        partial_fund_transaction,
    );

    let tumbler = puzzle_solver::Tumbler::new(params.clone(), he_keypair, &mut thread_rng());
    let sender = sender::Sender::new(params, &mut thread_rng());

    let tumbler_starting_balance = tumbler_wallet.get_balance()?;
    let sender_starting_balance = sender_wallet.get_balance()?;

    let tumbler = E2ETumblerSolver {
        inner: tumbler,
        wallet: tumbler_wallet,
        tumble_amount,
        tumbler_fee,
        starting_balance: tumbler_starting_balance,
    };
    let sender = E2ESender {
        inner: sender,
        wallet: sender_wallet,
        starting_balance: sender_starting_balance,
        fund_fee,
        tumbler_fee,
        tumble_amount,
        spend_tx_miner_fee,
    };

    Ok((tumbler, sender))
}

struct Wallet {
    url: String,
}

impl Wallet {
    fn new(url: String, name: String, mint_amount: Option<u64>) -> anyhow::Result<Wallet> {
        let _ = rpc_command::<SerdeValue>(
            &url,
            ureq::json!({"jsonrpc": "1.0", "method": "createwallet", "params": [name] }),
        )?;

        let wallet = Wallet {
            url: format!("{}/wallet/{}", url, name),
        };

        if let Some(mint_amount) = mint_amount {
            let _ = rpc_command::<SerdeValue>(
                &format!("{}/wallet/", &url),
                ureq::json!({"jsonrpc": "1.0", "method": "sendtoaddress", "params": [wallet.getnewaddress()?, mint_amount] }),
            ).context(format!("failed to mint {} for wallet {}", mint_amount, name))?;

            mine(&format!("{}/wallet/", &url))?;
        }

        Ok(wallet)
    }

    fn make_partial_fund_transaction(
        &self,
        sats: bitcoin::Amount,
    ) -> anyhow::Result<PartialFundTransaction> {
        let dummy_address = "bcrt1q6rhpng9evdsfnn833a4f4vej0asu6dk5srld6x";
        let transaction_hex = self.createrawtransaction(dummy_address, sats)?;

        let res = self.fundrawtransaction(transaction_hex)?;

        let mut transaction = deserialize::<bitcoin::Transaction>(&Vec::<u8>::from_hex(&res.hex)?)?;
        Ok(PartialFundTransaction {
            inner: bitcoin::Transaction {
                output: vec![transaction.output.remove(res.changepos as usize)],
                ..transaction
            },
            expected_fee: bitcoin::Amount::from_btc(res.fee)?,
        })
    }

    fn sign(&self, transaction: &bitcoin::Transaction) -> anyhow::Result<bitcoin::Transaction> {
        #[derive(Deserialize)]
        struct Response {
            hex: String,
        }

        let res = rpc_command::<Response>(
            &self.url,
            ureq::json!({"jsonrpc": "1.0", "method": "signrawtransactionwithwallet", "params": [serialize_hex(transaction)] }),
        )?;

        let transaction = deserialize::<bitcoin::Transaction>(&Vec::<u8>::from_hex(&res.hex)?)?;

        Ok(transaction)
    }

    fn get_balance(&self) -> anyhow::Result<bitcoin::Amount> {
        let balance = rpc_command::<f64>(
            &self.url,
            ureq::json!({"jsonrpc": "1.0", "method": "getbalance", "params": [] }),
        )?;
        let amount = bitcoin::Amount::from_btc(balance)?;

        Ok(amount)
    }

    fn getnewaddress(&self) -> anyhow::Result<String> {
        rpc_command::<String>(
            &self.url,
            ureq::json!({"jsonrpc": "1.0", "method": "getnewaddress", "params": ["", "bech32"] }),
        )
    }

    fn createrawtransaction(&self, address: &str, sats: bitcoin::Amount) -> anyhow::Result<String> {
        let btc = sats.as_btc();

        rpc_command::<String>(
            &self.url,
            ureq::json!({"jsonrpc": "1.0", "method": "createrawtransaction", "params": [[], { address:btc }] }),
        )
    }

    fn fundrawtransaction(&self, hex: String) -> anyhow::Result<FundRawTransactionResponse> {
        rpc_command::<FundRawTransactionResponse>(
            &self.url,
            ureq::json!({"jsonrpc": "1.0", "method": "fundrawtransaction", "params": [hex] }),
        )
    }
}

fn rpc_command<'a, T>(url: &str, body: SerdeValue) -> anyhow::Result<T>
where
    T: Deserialize<'a>,
{
    let json = ureq::post(url).send_json(body).into_json()?;

    match JsonRpcResponse::<T>::deserialize(json)? {
        JsonRpcResponse {
            result: Some(t), ..
        } => Ok(t),
        JsonRpcResponse { error: Some(e), .. } => Err(e.into()),
        _ => Err(anyhow::anyhow!("invalid jsonrpc")),
    }
}

fn mine(url: &str) -> anyhow::Result<()> {
    let dummy_address = "bcrt1q6rhpng9evdsfnn833a4f4vej0asu6dk5srld6x";
    let _ = rpc_command::<SerdeValue>(
        &url,
        ureq::json!({"jsonrpc": "1.0", "method": "generatetoaddress", "params": [1, dummy_address] }),
    )?;

    Ok(())
}

struct PartialFundTransaction {
    inner: bitcoin::Transaction,
    expected_fee: bitcoin::Amount,
}

#[derive(Deserialize)]
struct FundRawTransactionResponse {
    hex: String,
    changepos: i8,
    fee: f64,
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize, thiserror::Error)]
#[error("{message}")]
struct JsonRpcError {
    code: i32,
    message: String,
}
