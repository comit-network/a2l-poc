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

pub struct VerificationError;

impl System {
    pub fn new() -> Self {
        Self
    }

    pub fn keygen(&self) -> KeyPair {
        KeyPair::default()
    }

    pub fn encrypt<S: AsRef<secp256k1::SecretKey>>(
        &self,
        _keypair: &KeyPair,
        secret_key: &S,
    ) -> (Ciphertext, Proof) {
        let ciphertext = Ciphertext {
            sk: secret_key.as_ref().clone(),
        };
        let proof = Proof;

        (ciphertext, proof)
    }

    pub fn verify(
        &self,
        _pk: PublicKey,
        _ciphertext: Ciphertext,
        _proof: Proof,
    ) -> Result<(), VerificationError> {
        Ok(())
    }

    pub fn decrypt(&self, _keypair: &KeyPair, ciphertext: Ciphertext) -> secp256k1::SecretKey // Result<super::SecretKey, DecryptionError>
    {
        ciphertext.sk
    }

    pub fn multiply(&self, ciphertext: Ciphertext, _sk: &secp256k1::SecretKey) -> Ciphertext {
        ciphertext
    }
}
