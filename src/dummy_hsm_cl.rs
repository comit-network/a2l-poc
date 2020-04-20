use crate::secp256k1;

#[derive(Default)]
pub struct Message;

#[derive(Clone, Debug)]
pub struct Ciphertext {
    sk: secp256k1::SecretKey,
}

#[derive(Default, Clone)]
pub struct Proof;

#[derive(Default)]
pub struct SecretKey;

#[derive(Default)]
pub struct PublicKey;

pub struct System<K> {
    _key: K,
}

/// Capability marker trait for making new puzzles.
pub trait Make {}

/// Capability marker trait for randomizing puzzles.
pub trait Randomize {}

/// Capability marker trait for verifying puzzles.
pub trait Verify {}

/// Capability marker trait for solving puzzles.
pub trait Solve {}

/// New puzzles can only be created if the system was initialized with a secret key.
impl Make for SecretKey {}

/// The remaining capabilities are supported by both keys. (TODO: Is this true?)
impl Randomize for SecretKey {}
impl Verify for SecretKey {}
impl Solve for SecretKey {}
impl Randomize for PublicKey {}
impl Verify for PublicKey {}
impl Solve for PublicKey {}

#[derive(thiserror::Error, Debug)]
#[error("verification of the puzzle failed")]
pub struct VerificationError;

#[derive(Clone, Debug)]
pub struct Puzzle {
    pub c_alpha: Ciphertext,
    pub A: secp256k1::PublicKey,
}

pub fn keygen() -> (SecretKey, PublicKey) {
    (SecretKey, PublicKey)
}

impl<C> System<C> {
    pub fn new(key: C) -> Self {
        Self { _key: key }
    }
}

impl<C: Make> System<C> {
    pub fn make_puzzle(&self, x: &secp256k1::KeyPair, a: &secp256k1::KeyPair) -> (Proof, Puzzle) {
        let ciphertext = Ciphertext {
            sk: x.as_ref().clone(),
        };
        let pi_alpha = Proof;

        let l = Puzzle {
            c_alpha: ciphertext,
            A: a.to_pk(),
        };

        (pi_alpha, l)
    }
}

impl<K: Randomize> System<K> {
    pub fn randomize_puzzle(&self, l: &Puzzle, _beta: &secp256k1::KeyPair) -> Puzzle {
        l.clone()
    }
}

impl<K: Verify> System<K> {
    pub fn verify_puzzle(
        &self,
        _pi_alpha: Proof,
        _puzzle: &Puzzle,
    ) -> Result<(), VerificationError> {
        Ok(())
    }
}

impl<K: Solve> System<K> {
    pub fn solve_puzzle(&self, puzzle: Puzzle, _x: &secp256k1::KeyPair) -> secp256k1::SecretKey {
        puzzle.c_alpha.sk
    }
}
