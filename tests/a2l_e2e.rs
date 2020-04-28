use a2l_poc::puzzle_promise;
use a2l_poc::puzzle_solver;
use a2l_poc::{dummy_hsm_cl as hsm_cl, Params};
use anyhow::Context;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::hex::FromHex;
use rand::SeedableRng;
use serde::*;
use testcontainers::{clients, images::coblox_bitcoincore::BitcoinCore, Docker};
use ureq::SerdeValue;

#[test]
fn a2l_happy_path() -> anyhow::Result<()> {
    let client = clients::Cli::default();
    let container = client.run(BitcoinCore::default().with_tag("0.19.1"));
    let port = container.get_host_port(18443);

    let auth = container.image().auth();
    let url = format!(
        "http://{}:{}@localhost:{}",
        &auth.username,
        &auth.password,
        port.unwrap()
    );

    {
        let address = rpc_command::<String>(
            &url,
            ureq::json!({"jsonrpc": "1.0", "method": "getnewaddress", "params": ["", "bech32"] }),
        )?;
        let _ = rpc_command::<Vec<String>>(
            &url,
            ureq::json!({"jsonrpc": "1.0", "method": "generatetoaddress", "params": [101, address] }),
        )?;
    }

    let tumbler_wallet = Wallet::new(url.clone(), String::from("tumbler"), Some(10))?;
    let receiver_wallet = Wallet::new(url.clone(), String::from("receiver"), None)?;
    let sender_wallet = Wallet::new(url.clone(), String::from("sender"), Some(10))?;

    let redeem_address = receiver_wallet.getnewaddress()?;
    let refund_address = tumbler_wallet.getnewaddress()?;
    let tumble_amount = 10_000_000;
    let spend_transaction_fee_per_wu = 10;
    let partial_fund_transaction = tumbler_wallet
        .make_fund_transaction(tumble_amount + a2l_poc::bitcoin::MAX_SATISFACTION_WEIGHT * 10)?;

    let params = Params::new(
        redeem_address.parse()?,
        refund_address.parse()?,
        0,
        tumble_amount,
        0,
        spend_transaction_fee_per_wu,
        partial_fund_transaction,
    );

    let mut rng = rand::rngs::StdRng::seed_from_u64(123_456);
    let (secretkey, publickey) = hsm_cl::keygen();

    // puzzle promise protocol
    let tumbler = puzzle_promise::Tumbler0::new(params.clone(), &mut rng);
    let receiver = puzzle_promise::Receiver0::new(params, &mut rng);
    let sender = puzzle_promise::Sender0::new();

    let message = tumbler.next_message(&secretkey);
    let receiver = receiver.receive(message)?;
    let message = receiver.next_message();
    let tumbler = tumbler.receive(message)?;
    let message = tumbler.next_message(&mut rng);
    let receiver = receiver.receive(message, &mut rng, &publickey)?;
    let message = receiver.next_message();
    let sender = sender.receive(message);

    tumbler_wallet
        .sign_and_send(tumbler.unsigned_fund_transaction())
        .context("failed to sign and broadcast fund transaction for tumbler")?;
    let _ = rpc_command::<SerdeValue>(
        &url,
        ureq::json!({"jsonrpc": "1.0", "method": "generatetoaddress", "params": [1, "bcrt1q6rhpng9evdsfnn833a4f4vej0asu6dk5srld6x"] }),
    )?;

    // puzzle solver protocol
    let redeem_address = tumbler_wallet.getnewaddress()?;
    let refund_address = sender_wallet.getnewaddress()?;

    let tumbler_fee = 10_000;
    let partial_fund_transaction = sender_wallet.make_fund_transaction(
        tumble_amount + tumbler_fee + a2l_poc::bitcoin::MAX_SATISFACTION_WEIGHT * 10,
    )?;

    let params = Params::new(
        redeem_address.parse()?,
        refund_address.parse()?,
        0,
        tumble_amount,
        tumbler_fee,
        spend_transaction_fee_per_wu,
        partial_fund_transaction,
    );

    let tumbler = puzzle_solver::Tumbler0::new(params.clone(), tumbler.x_t().clone());
    let sender = puzzle_solver::Sender0::new(params, sender.lock().clone(), &mut rng);
    let receiver = puzzle_solver::Receiver0::new(
        receiver.x_r().to_pk(),
        receiver.X_t().clone(),
        receiver.unsigned_redeem_transaction().clone(),
        receiver.sig_redeem_t().clone(),
        receiver.sig_redeem_r().clone(),
        receiver.beta().clone(),
        *receiver.redeem_tx_digest(),
    );

    let message = tumbler.next_message();
    let sender = sender.receive(message, &mut rng);
    let message = sender.next_message(&publickey);
    let tumbler = tumbler.receive(message, &secretkey);
    let message = tumbler.next_message();
    let sender = sender.receive(message, &mut rng, &publickey).unwrap();
    let message = sender.next_message();
    let tumbler = tumbler.receive(message).unwrap();

    sender_wallet
        .sign_and_send(&sender.unsigned_fund_transaction())
        .context("failed to sign and broadcast fund transaction for sender")?;
    let _ = rpc_command::<SerdeValue>(
        &url,
        ureq::json!({"jsonrpc": "1.0", "method": "generatetoaddress", "params": [1, "bcrt1q6rhpng9evdsfnn833a4f4vej0asu6dk5srld6x"] }),
    )?;

    tumbler_wallet
        .send_transaction(tumbler.signed_redeem_transaction())
        .context("failed to broadcast redeem transaction for tumbler")?;
    let _ = rpc_command::<SerdeValue>(
        &url,
        ureq::json!({"jsonrpc": "1.0", "method": "generatetoaddress", "params": [1, "bcrt1q6rhpng9evdsfnn833a4f4vej0asu6dk5srld6x"] }),
    )?;

    let sender = sender.receive(tumbler.signed_redeem_transaction().clone())?;
    let message = sender.next_message();
    let receiver = receiver.receive(message)?;

    receiver_wallet
        .send_transaction(&receiver.signed_redeem_transaction())
        .context("failed to broadcast redeem transaction for receiver")?;
    let _ = rpc_command::<SerdeValue>(
        &url,
        ureq::json!({"jsonrpc": "1.0", "method": "generatetoaddress", "params": [1, "bcrt1q6rhpng9evdsfnn833a4f4vej0asu6dk5srld6x"] }),
    )?;

    Ok(())
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
            )?;
        }

        Ok(wallet)
    }

    fn getbalance(&self) -> anyhow::Result<f64> {
        rpc_command::<f64>(
            &self.url,
            ureq::json!({"jsonrpc": "1.0", "method": "getbalance", "params": [] }),
        )
    }

    fn getnewaddress(&self) -> anyhow::Result<String> {
        rpc_command::<String>(
            &self.url,
            ureq::json!({"jsonrpc": "1.0", "method": "getnewaddress", "params": ["", "bech32"] }),
        )
    }

    fn make_fund_transaction(&self, sats: u64) -> anyhow::Result<bitcoin::Transaction> {
        let dummy_address = "bcrt1q6rhpng9evdsfnn833a4f4vej0asu6dk5srld6x";
        let transaction_hex = self.createrawtransaction(dummy_address, sats)?;

        let res = self.fundrawtransaction(transaction_hex)?;

        let mut transaction = deserialize::<bitcoin::Transaction>(&Vec::<u8>::from_hex(&res.hex)?)?;
        Ok(bitcoin::Transaction {
            output: vec![transaction.output.remove(res.changepos as usize)],
            ..transaction
        })
    }

    fn sign_and_send(&self, transaction: &bitcoin::Transaction) -> anyhow::Result<()> {
        #[derive(Deserialize)]
        struct Response {
            hex: String,
        }

        let res = rpc_command::<Response>(
            &self.url,
            ureq::json!({"jsonrpc": "1.0", "method": "signrawtransactionwithwallet", "params": [serialize_hex(transaction)] }),
        )?;
        self.sendrawtransaction(&res.hex)
    }

    fn send_transaction(&self, transaction: &bitcoin::Transaction) -> anyhow::Result<()> {
        self.sendrawtransaction(&serialize_hex(transaction))
    }

    fn sendrawtransaction(&self, hex: &str) -> anyhow::Result<()> {
        rpc_command::<SerdeValue>(
            &self.url,
            ureq::json!({"jsonrpc": "1.0", "method": "sendrawtransaction", "params": [ hex ] }),
        )
        .map(|_| ())
    }

    fn createrawtransaction(&self, address: &str, sats: u64) -> anyhow::Result<String> {
        let btc = sats as f64 / 100_000_000.0;

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

#[derive(Deserialize)]
pub struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize, thiserror::Error)]
#[error("{message}")]
pub struct JsonRpcError {
    code: i32,
    message: String,
}

#[derive(Deserialize)]
struct FundRawTransactionResponse {
    hex: String,
    changepos: i8,
}
