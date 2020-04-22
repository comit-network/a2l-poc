use a2l_poc::puzzle_promise;
use a2l_poc::puzzle_solver;
use a2l_poc::{dummy_hsm_cl as hsm_cl, Params};
use rand::Rng;

#[test]
fn happy_path() {
    let mut rng = rand::thread_rng();
    let (secretkey, publickey) = hsm_cl::keygen();

    let params = make_params(&mut rng);
    let mut blockchain = Blockchain::default();

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

    let params = make_params(&mut rng);

    // puzzle solver protocol
    let tumbler = puzzle_solver::Tumbler0::new(params.clone(), tumbler.x_t().clone());
    let sender = puzzle_solver::Sender0::new(params, sender.lock().clone(), &mut rng);
    let receiver = puzzle_solver::Receiver0::new(
        receiver.x_r().to_pk(),
        receiver.X_t().clone(),
        receiver.unsigned_redeem_transaction().clone(),
        receiver.sig_redeem_t().clone(),
        receiver.sig_redeem_r().clone(),
        receiver.beta().clone(),
    );

    let message = tumbler.next_message();
    let sender = sender.receive(message, &mut rng);
    let message = sender.next_message(&publickey);
    let tumbler = tumbler.receive(message, &secretkey);
    let message = tumbler.next_message();
    let sender = sender.receive(message, &mut rng, &publickey).unwrap();
    let message = sender.next_message();
    let tumbler = tumbler.receive(message).unwrap();
    blockchain.broadcast(tumbler.signed_redeem_transaction().clone());

    let sender = sender.receive(blockchain.latest_tx()).unwrap();
    let message = sender.next_message();
    let receiver = receiver.receive(message).unwrap();

    blockchain.broadcast(receiver.signed_redeem_transaction().clone());
}

fn make_params(mut rng: &mut impl Rng) -> Params {
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

#[derive(Default)]
struct Blockchain {
    transactions: Vec<bitcoin::Transaction>,
}

impl Blockchain {
    fn broadcast(&mut self, tx: bitcoin::Transaction) {
        self.transactions.push(tx)
    }

    fn latest_tx(&mut self) -> bitcoin::Transaction {
        self.transactions.pop().unwrap()
    }
}
