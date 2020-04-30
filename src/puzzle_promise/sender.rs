use crate::puzzle_promise::Message3;
use crate::Lock;

pub struct Sender0;

#[derive(Debug)]
pub struct Sender1 {
    l: Lock,
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
