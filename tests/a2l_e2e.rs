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

fn make_fund_transaction(sats: u64, url: &str) -> anyhow::Result<bitcoin::Transaction> {
    #[derive(Deserialize)]
    struct Response {
        hex: String,
        changepos: i8,
    }

    let dummy_address = "bcrt1q6rhpng9evdsfnn833a4f4vej0asu6dk5srld6x";
    let btc = sats as f64 / 100_000_000.0;

    let transaction_hex = rpc_command::<String>(
        url,
        ureq::json!({"jsonrpc": "1.0", "method": "createrawtransaction", "params": [[], { dummy_address:btc }] }),
    )?;
    let res = rpc_command::<Response>(
        url,
        ureq::json!({"jsonrpc": "1.0", "method": "fundrawtransaction", "params": [transaction_hex] }),
    )?;

    let mut transaction = deserialize::<bitcoin::Transaction>(&Vec::<u8>::from_hex(&res.hex)?)?;
    Ok(bitcoin::Transaction {
        output: vec![transaction.output.remove(res.changepos as usize)],
        ..transaction
    })
}

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

    let address = rpc_command::<String>(
        &url,
        ureq::json!({"jsonrpc": "1.0", "method": "getnewaddress", "params": ["", "bech32"] }),
    )?;
    let _ = rpc_command::<Vec<String>>(
        &url,
        ureq::json!({"jsonrpc": "1.0", "method": "generatetoaddress", "params": [101, address] }),
    )?;

    let tumbler_wallet = "tumbler";
    let receiver_wallet = "receiver";
    let sender_wallet = "sender";

    let _ = rpc_command::<SerdeValue>(
        &url,
        ureq::json!({"jsonrpc": "1.0", "method": "createwallet", "params": [tumbler_wallet] }),
    )?;
    let _ = rpc_command::<SerdeValue>(
        &url,
        ureq::json!({"jsonrpc": "1.0", "method": "createwallet", "params": [receiver_wallet] }),
    )?;
    let _ = rpc_command::<SerdeValue>(
        &url,
        ureq::json!({"jsonrpc": "1.0", "method": "createwallet", "params": [sender_wallet] }),
    )?;

    let address = rpc_command::<String>(
        &format!("{}/wallet/{}", url, tumbler_wallet),
        ureq::json!({"jsonrpc": "1.0", "method": "getnewaddress", "params": ["", "bech32"] }),
    )?;
    let _ = rpc_command::<SerdeValue>(
        &url,
        ureq::json!({"jsonrpc": "1.0", "method": "generatetoaddress", "params": [100, address] }),
    )?;

    let address = rpc_command::<String>(
        &format!("{}/wallet/{}", url, sender_wallet),
        ureq::json!({"jsonrpc": "1.0", "method": "getnewaddress", "params": ["", "bech32"] }),
    )?;
    let _ = rpc_command::<SerdeValue>(
        &url,
        ureq::json!({"jsonrpc": "1.0", "method": "generatetoaddress", "params": [100, address] }),
    )?;

    let redeem_address = rpc_command::<String>(
        &format!("{}/wallet/{}", url, receiver_wallet),
        ureq::json!({"jsonrpc": "1.0", "method": "getnewaddress", "params": ["", "bech32"] }),
    )?;
    let refund_address = rpc_command::<String>(
        &format!("{}/wallet/{}", url, tumbler_wallet),
        ureq::json!({"jsonrpc": "1.0", "method": "getnewaddress", "params": ["", "bech32"] }),
    )?;

    let amount = 10_000_000;
    let params = Params::new(
        redeem_address.parse()?,
        refund_address.parse()?,
        0,
        amount,
        0,
        10,
        make_fund_transaction(
            amount + a2l_poc::bitcoin::MAX_SATISFACTION_WEIGHT * 10,
            &format!("{}/wallet/{}", url, tumbler_wallet),
        )?,
    );

    let mut rng = rand::rngs::StdRng::seed_from_u64(123456);
    let (secretkey, publickey) = hsm_cl::keygen();

    // puzzle promise protocol
    let tumbler = puzzle_promise::Tumbler0::new(params.clone(), &mut rng);
    let receiver = puzzle_promise::Receiver0::new(params, &mut rng);
    let sender = puzzle_promise::Sender0::new();

    let message = tumbler.next_message(&secretkey);
    let receiver = receiver.receive(message).unwrap();
    let message = receiver.next_message();
    let tumbler = tumbler.receive(message).unwrap();
    let message = tumbler.next_message(&mut rng);
    let receiver = receiver.receive(message, &mut rng, &publickey).unwrap();
    let message = receiver.next_message();
    let sender = sender.receive(message);

    let res = rpc_command::<SerdeValue>(
        &format!("{}/wallet/{}", url, tumbler_wallet),
        ureq::json!({"jsonrpc": "1.0", "method": "signrawtransactionwithwallet", "params": [serialize_hex(tumbler.unsigned_fund_transaction())] }),
    )?;
    let _ = rpc_command::<SerdeValue>(
        &format!("{}/wallet/{}", url, tumbler_wallet),
        ureq::json!({"jsonrpc": "1.0", "method": "sendrawtransaction", "params": [ res["hex"].as_str().unwrap() ] }),
    )?;
    let _ = rpc_command::<SerdeValue>(
        &url,
        ureq::json!({"jsonrpc": "1.0", "method": "generatetoaddress", "params": [1, "bcrt1q6rhpng9evdsfnn833a4f4vej0asu6dk5srld6x"] }),
    )?;

    // puzzle solver protocol
    let redeem_address = rpc_command::<String>(
        &format!("{}/wallet/{}", url, tumbler_wallet),
        ureq::json!({"jsonrpc": "1.0", "method": "getnewaddress", "params": ["", "bech32"] }),
    )?;
    let refund_address = rpc_command::<String>(
        &format!("{}/wallet/{}", url, sender_wallet),
        ureq::json!({"jsonrpc": "1.0", "method": "getnewaddress", "params": ["", "bech32"] }),
    )?;

    let params = Params::new(
        redeem_address.parse()?,
        refund_address.parse()?,
        0,
        amount,
        10_000,
        10,
        make_fund_transaction(
            amount + 10_000 + a2l_poc::bitcoin::MAX_SATISFACTION_WEIGHT * 10,
            &format!("{}/wallet/{}", url, sender_wallet),
        )?,
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
        receiver.redeem_tx_digest().clone(),
    );

    let message = tumbler.next_message();
    let sender = sender.receive(message, &mut rng);
    let message = sender.next_message(&publickey);
    let tumbler = tumbler.receive(message, &secretkey);
    let message = tumbler.next_message();
    let sender = sender.receive(message, &mut rng, &publickey).unwrap();
    let message = sender.next_message();
    let tumbler = tumbler.receive(message).unwrap();

    let res = rpc_command::<SignRawTransactionWithWalletResponse>(
        &format!("{}/wallet/{}", url, sender_wallet),
        ureq::json!({"jsonrpc": "1.0", "method": "signrawtransactionwithwallet", "params": [serialize_hex(&sender.unsigned_fund_transaction())] }),
    )?;

    let _ = rpc_command::<String>(
        &format!("{}/wallet/{}", url, sender_wallet),
        ureq::json!({"jsonrpc": "1.0", "method": "sendrawtransaction", "params": [ res.hex ] }),
    )
    .context("failed to broadcast fund transaction for sender")?;

    let _ = rpc_command::<SerdeValue>(
        &url,
        ureq::json!({"jsonrpc": "1.0", "method": "generatetoaddress", "params": [1, "bcrt1q6rhpng9evdsfnn833a4f4vej0asu6dk5srld6x"] }),
    )?;

    let signed_redeem_transaction = tumbler.signed_redeem_transaction();
    let signed_redeem_transaction = serialize_hex(signed_redeem_transaction);

    let _ = rpc_command::<String>(
        &format!("{}/wallet/{}", url, tumbler_wallet),
        ureq::json!({"jsonrpc": "1.0", "method": "sendrawtransaction", "params": [signed_redeem_transaction] }),
    )
    .context("failed to broadcast redeem transaction for tumbler")?;
    let _ = rpc_command::<SerdeValue>(
        &url,
        ureq::json!({"jsonrpc": "1.0", "method": "generatetoaddress", "params": [1, "bcrt1q6rhpng9evdsfnn833a4f4vej0asu6dk5srld6x"] }),
    )?;

    let sender = sender
        .receive(tumbler.signed_redeem_transaction().clone())
        .unwrap();
    let message = sender.next_message();
    let receiver = receiver.receive(message).unwrap();

    let signed_redeem_transaction = serialize_hex(receiver.signed_redeem_transaction());

    let _ = rpc_command::<String>(
        &format!("{}/wallet/{}", url, receiver_wallet),
        ureq::json!({"jsonrpc": "1.0", "method": "sendrawtransaction", "params": [signed_redeem_transaction] }),
    ).context("failed to broadcast redeem transaction for receiver")?;
    let _ = rpc_command::<SerdeValue>(
        &url,
        ureq::json!({"jsonrpc": "1.0", "method": "generatetoaddress", "params": [1, "bcrt1q6rhpng9evdsfnn833a4f4vej0asu6dk5srld6x"] }),
    )?;

    Ok(())
}

#[derive(Deserialize)]
struct SignRawTransactionWithWalletResponse {
    hex: String,
}
