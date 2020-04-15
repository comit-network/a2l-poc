use crate::dummy_hsmcl;
use crate::*;

pub struct Tumbler0;

pub struct Sender0;

pub struct Receiver0;

pub struct Sender1;

pub struct Tumbler1;

pub struct Receiver1;

pub struct Receiver2;

impl Receiver0 {
    pub fn new(params: Params) -> Self {
        Self
    }

    pub fn receive(self, message: Message0) -> Receiver1 {
        Receiver1
    }
}

impl Receiver1 {
    pub fn next_message(&self) -> Message1 {
        Message1::default()
    }

    pub fn receive(self, message: Message2) -> Receiver2 {
        Receiver2
    }
}

impl Tumbler0 {
    pub fn new(params: Params) -> Self {
        Self
    }

    pub fn next_message(&self) -> Message0 {
        Message0::default()
    }

    pub fn receive(self, message: Message1) -> Tumbler1 {
        Tumbler1
    }
}

impl Tumbler1 {
    pub fn next_message(&self) -> Message2 {
        Message2::default()
    }
}

impl Receiver2 {
    pub fn next_message(&self) -> Message3 {
        Message3::default()
    }
}

impl Sender0 {
    pub fn new() -> Self {
        Self
    }

    pub fn receive(self, message: Message3) -> Sender1 {
        Sender1
    }
}

#[derive(Default)]
pub struct Message0 {
    // key generation
    tumbler_pk: PublicKey,
    // protocol
    A: PublicKey,
    pi_alpha: dummy_hsmcl::Proof,
    c_alpha: dummy_hsmcl::Ciphertext,
}

#[derive(Default)]
pub struct Message1 {
    // key generation
    receiver_pk: PublicKey,
    // protocol
    refund_sig: Signature,
}

#[derive(Default)]
pub struct Message2 {
    redeem_encsig: EncryptedSignature,
}

// receiver to sender
#[derive(Default)]
pub struct Message3 {
    A_prime: PublicKey,
    c_alpha_prime: dummy_hsmcl::Ciphertext,
}
