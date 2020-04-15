use crate::secp256k1;

#[derive(Default, Clone)]
pub struct PublicKey;

#[derive(Default)]
pub struct SecretKey;

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

#[derive(Default)]
pub struct KeyPair {
    sk: SecretKey,
    pk: PublicKey,
}

impl KeyPair {
    pub fn to_pk(&self) -> PublicKey {
        self.pk.clone()
    }
}

#[derive(thiserror::Error, Debug)]
#[error("verification of the puzzle failed")]
pub struct VerificationError;

#[derive(Clone)]
pub struct Puzzle {
    c_alpha: Ciphertext,
    A: PublicKey,
}

impl System {
    pub fn make_puzzle(&self, x: &secp256k1::KeyPair) -> (KeyPair, Proof, Puzzle) {
        let a = self.keygen();
        let (c_alpha, pi_alpha) = self.encrypt(&a, &x);

        let l = Puzzle {
            c_alpha,
            A: a.to_pk(),
        };

        (a, pi_alpha, l)
    }

    pub fn randomize_puzzle(&self, l: &Puzzle) -> (KeyPair, Puzzle) {
        (self.keygen(), l.clone())
    }

    pub fn solve_puzzle(&self, puzzle: Puzzle, _x: &KeyPair) -> secp256k1::SecretKey // Result<super::SecretKey, DecryptionError>
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

    fn keygen(&self) -> KeyPair {
        KeyPair::default()
    }

    fn encrypt<S: AsRef<secp256k1::SecretKey>>(
        &self,
        _keypair: &KeyPair,
        secret_key: &S,
    ) -> (Ciphertext, Proof) {
        let ciphertext = Ciphertext {
            sk: *secret_key.as_ref(),
        };
        let proof = Proof;

        (ciphertext, proof)
    }
}
