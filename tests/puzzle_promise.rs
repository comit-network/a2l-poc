use a2l_poc::{dummy_hsm_cl as hsm_cl, puzzle_promise, secp256k1, Params};
use fehler::throws;
use std::rc::Rc;

#[test]
#[throws(anyhow::Error)]
fn happy_path() {
    let mut rng = rand::thread_rng();

    let (secretkey, publickey) = hsm_cl::keygen();

    let hsm_cl_t = Rc::new(hsm_cl::System::new(secretkey));
    let hsm_cl_r = Rc::new(hsm_cl::System::new(publickey));

    let redeem_identity = secp256k1::SecretKey::random(&mut rng);
    let refund_identity = secp256k1::SecretKey::random(&mut rng);

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

    let receiver = puzzle_promise::Receiver0::new(params.clone(), hsm_cl_r, &mut rng);
    let tumbler = puzzle_promise::Tumbler0::new(params, hsm_cl_t, &mut rng);
    let sender = puzzle_promise::Sender0::new();

    let message = tumbler.next_message();
    let receiver = receiver.receive(message)?;

    let message = receiver.next_message();
    let tumbler = tumbler.receive(message);

    let message = tumbler.next_message(&mut rng);
    let receiver = receiver.receive(message, &mut rng);

    let message = receiver.next_message();
    let _sender = sender.receive(message);
}
