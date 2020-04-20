use a2l_poc::{dummy_hsm_cl as hsm_cl, puzzle_promise, secp256k1, Params};
use fehler::throws;

#[test]
#[throws(anyhow::Error)]
fn happy_path() {
    let mut rng = rand::thread_rng();
    let (secretkey, publickey) = hsm_cl::keygen();

    let params = make_params(&mut rng);

    let receiver = puzzle_promise::Receiver0::new(params.clone(), publickey, &mut rng);
    let tumbler = puzzle_promise::Tumbler0::new(params, secretkey, &mut rng);
    let sender = puzzle_promise::Sender0::new();

    let tumbler_output = run_protocol(&mut rng, receiver, tumbler, sender);

    println!("{:#?}", tumbler_output);
}

fn make_params<R: rand::Rng>(mut rng: &mut R) -> Params {
    let redeem_identity = secp256k1::SecretKey::random(&mut rng);
    let refund_identity = secp256k1::SecretKey::random(&mut rng);

    Params {
        redeem_identity: secp256k1::PublicKey::from_secret_key(&redeem_identity),
        refund_identity: secp256k1::PublicKey::from_secret_key(&refund_identity),
        expiry: 0,
        amount: 10000,
        partial_fund_transaction: bitcoin::Transaction {
            lock_time: 0,
            version: 2,
            input: Vec::new(),  // TODO: fill these from a `fundrawtransaction` call
            output: Vec::new(), // TODO: fill these from a `fundrawtransaction` call
        },
    }
}

#[throws(anyhow::Error)]
fn run_protocol<R: rand::Rng>(
    mut rng: &mut R,
    receiver: puzzle_promise::Receiver0,
    tumbler: puzzle_promise::Tumbler0,
    sender: puzzle_promise::Sender0,
) -> puzzle_promise::TumblerOutput {
    let message = tumbler.next_message();
    let receiver = receiver.receive(message)?;
    let message = receiver.next_message();
    let tumbler = tumbler.receive(message)?;
    let message = tumbler.next_message(&mut rng);
    let receiver = receiver.receive(message, &mut rng);
    let message = receiver.next_message();
    let sender = sender.receive(message);

    tumbler.output()?
}
