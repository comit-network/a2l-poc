use a2l_poc::{dummy_hsm_cl as hsm_cl, puzzle_promise, secp256k1, Params};
use fehler::throws;
use std::rc::Rc;

#[test]
#[throws(anyhow::Error)]
fn happy_path() {
    let mut rnd = rand::thread_rng();
    let hsm_cl = Rc::new(hsm_cl::System::default());

    let redeem_identity = secp256k1::SecretKey::random(&mut rnd);
    let refund_identity = secp256k1::SecretKey::random(&mut rnd);

    let params = Params {
        redeem_identity: secp256k1::PublicKey::from_secret_key(&redeem_identity),
        refund_identity: secp256k1::PublicKey::from_secret_key(&refund_identity),
        expiry: 0,
        amount: 10000,
        partial_fund_transaction: bitcoin::Transaction {
            lock_time: 0,
            version: 1,
            input: Vec::new(),  // TODO: fill these from a `fundrawtransaction` call
            output: Vec::new(), // TODO: fill these from a `fundrawtransaction` call
        },
    };

    let receiver = puzzle_promise::Receiver0::new(
        params.clone(),
        secp256k1::KeyPair::random(&mut rnd),
        hsm_cl.clone(),
    );
    let tumbler =
        puzzle_promise::Tumbler0::new(params, secp256k1::KeyPair::random(&mut rnd), hsm_cl);
    let sender = puzzle_promise::Sender0::new();

    let message = tumbler.next_message();
    let receiver = receiver.receive(message)?;

    let message = receiver.next_message();
    let tumbler = tumbler.receive(message);

    let message = tumbler.next_message();
    let receiver = receiver.receive(message);

    let message = receiver.next_message();
    let _sender = sender.receive(message);
}
