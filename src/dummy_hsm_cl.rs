use crate::secp256k1;

#[derive(Default)]
pub struct Message;

#[derive(Clone)]
pub struct Ciphertext {
    sk: secp256k1::SecretKey,
}

#[derive(Default, Clone)]
pub struct Proof;

#[derive(Default)]
pub struct System;

#[derive(thiserror::Error, Debug)]
#[error("verification of the puzzle failed")]
pub struct VerificationError;

#[derive(Clone)]
pub struct Puzzle {
    c_alpha: Ciphertext,
    A: secp256k1::PublicKey,
}

impl System {
    pub fn make_puzzle<R: rand::Rng>(
        &self,
        rng: &mut R,
        x: &secp256k1::KeyPair,
    ) -> (secp256k1::KeyPair, Proof, Puzzle) {
        let a = self.keygen(rng);
        let (c_alpha, pi_alpha) = self.encrypt(&a, &x);

        let l = Puzzle {
            c_alpha,
            A: a.to_pk(),
        };

        (a, pi_alpha, l)
    }

    pub fn randomize_puzzle<R: rand::Rng>(
        &self,
        rng: &mut R,
        l: &Puzzle,
    ) -> (secp256k1::KeyPair, Puzzle) {
        (self.keygen(rng), l.clone())
    }

    pub fn solve_puzzle(&self, puzzle: Puzzle, _x: &secp256k1::KeyPair) -> secp256k1::SecretKey // Result<super::SecretKey, DecryptionError>
    {
        puzzle.c_alpha.sk
    }

    pub fn verify_puzzle(
        &self,
        _pi_alpha: Proof,
        _puzzle: &Puzzle,
    ) -> Result<(), VerificationError> {
        Ok(())
    }

    fn keygen<R: rand::Rng>(&self, rng: &mut R) -> secp256k1::KeyPair {
        secp256k1::KeyPair::random(rng)
    }

    fn encrypt<S: AsRef<secp256k1::SecretKey>>(
        &self,
        _keypair: &secp256k1::KeyPair,
        secret_key: &S,
    ) -> (Ciphertext, Proof) {
        let ciphertext = Ciphertext {
            sk: secret_key.as_ref().clone(),
        };
        let proof = Proof;

        (ciphertext, proof)
    }
}
