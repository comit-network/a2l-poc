use crate::puzzle_promise::Message3;
use crate::Lock;

pub struct Sender0;

#[derive(Debug)]
pub struct Sender1 {
    l: Lock,
}

#[derive(Debug)]
pub enum In {
    Message3(Message3),
}

#[derive(Debug)]
pub struct Return {
    l: Lock,
}

impl From<Sender1> for Return {
    fn from(sender: Sender1) -> Self {
        Self { l: sender.l }
    }
}

impl Sender0 {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self
    }

    pub fn receive(self, message: Message3) -> Sender1 {
        Sender1 { l: message.l }
    }
}

impl Sender1 {
    pub fn lock(&self) -> &Lock {
        &self.l
    }
}
