pub use bitcoin::secp256k1::*;

pub struct KeyPair {
    sk: SecretKey,
    pk: PublicKey,
}

impl AsRef<SecretKey> for KeyPair {
    fn as_ref(&self) -> &SecretKey {
        &self.sk
    }
}

impl KeyPair {
    pub fn random<R: rand::Rng, C: Signing>(rand: &mut R, context: &Secp256k1<C>) -> Self {
        let sk = SecretKey::new(rand);
        let pk = PublicKey::from_secret_key(context, &sk);

        Self { sk, pk }
    }

    pub fn to_pk(&self) -> PublicKey {
        self.pk
    }
}
