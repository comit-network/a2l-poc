use bitcoin::secp256k1;

#[derive(Default, Clone)]
pub struct PublicKey;

#[derive(Default)]
pub struct SecretKey;

#[derive(Default)]
pub struct Message;

#[derive(Default, Clone)]
pub struct Ciphertext;

#[derive(Default, Clone)]
pub struct Proof;

pub struct System {}

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
        unimplemented!()
    }

    pub fn keygen(&self) -> KeyPair {
        unimplemented!()
    }

    pub fn encrypt<S: AsRef<secp256k1::SecretKey>>(
        &self,
        _keypair: &KeyPair,
        _message: &S,
    ) -> (Ciphertext, Proof) {
        unimplemented!()
    }

    pub fn verify(
        &self,
        _pk: PublicKey,
        _ciphertext: Ciphertext,
        _proof: Proof,
    ) -> Result<(), VerificationError> {
        unimplemented!()
    }

    pub fn decrypt(&self, _keypair: &KeyPair, _ciphertext: Ciphertext) -> secp256k1::SecretKey // Result<super::SecretKey, DecryptionError>
    {
        unimplemented!()
    }

    pub fn multiply(&self, _ciphertext: Ciphertext, _sk: &secp256k1::SecretKey) -> Ciphertext {
        unimplemented!()
    }
}
