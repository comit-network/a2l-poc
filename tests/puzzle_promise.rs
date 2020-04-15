use a2l_poc::{puzzle_promise, Params};

#[test]
fn happy_path() {
    let params = Params::default();

    let receiver = puzzle_promise::Receiver0::new(params.clone());
    let tumbler = puzzle_promise::Tumbler0::new(params);
    let sender = puzzle_promise::Sender0::new();

    let message = tumbler.next_message();
    let receiver = receiver.receive(message);

    let message = receiver.next_message();
    let tumbler = tumbler.receive(message);

    let message = tumbler.next_message();
    let receiver = receiver.receive(message);

    let message = receiver.next_message();
    let sender = sender.receive(message);
}
