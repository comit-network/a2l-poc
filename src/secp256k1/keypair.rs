use secp256k1::curve::Scalar;
use secp256k1::PublicKey;
use secp256k1::SecretKey;
use std::convert::TryFrom;

#[derive(PartialEq, Debug)]
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
    pub fn random<R: rand::Rng>(rand: &mut R) -> Self {
        let sk = SecretKey::random(rand);
        let pk = PublicKey::from_secret_key(&sk);

        Self { sk, pk }
    }

    pub fn to_pk(&self) -> PublicKey {
        self.pk.clone()
    }

    pub fn to_sk(&self) -> SecretKey {
        self.sk.clone()
    }

    pub fn into_sk(self) -> SecretKey {
        self.sk
    }
}

impl From<SecretKey> for KeyPair {
    fn from(secret_key: SecretKey) -> Self {
        Self {
            pk: PublicKey::from_secret_key(&secret_key),
            sk: secret_key,
        }
    }
}

impl TryFrom<Scalar> for KeyPair {
    type Error = secp256k1::Error;

    fn try_from(value: Scalar) -> Result<Self, Self::Error> {
        let secret_key = SecretKey::try_from(value)?;

        let pair = Self {
            pk: PublicKey::from_secret_key(&secret_key),
            sk: secret_key,
        };

        Ok(pair)
    }
}

pub trait XCoor {
    fn x_coor(&self) -> [u8; 32];
}

impl XCoor for PublicKey {
    fn x_coor(&self) -> [u8; 32] {
        let serialized_pk = self.serialize_compressed();

        let mut x_coor = [0u8; 32];
        // there's a random byte at the front of the uncompressed serialized pk
        x_coor.copy_from_slice(&serialized_pk[1..33]);
        x_coor
    }
}

#[cfg(test)]
impl KeyPair {
    pub fn random_from_thread_rng() -> Self {
        let sk = SecretKey::random(&mut rand::thread_rng());
        let pk = PublicKey::from_secret_key(&sk);

        Self { sk, pk }
    }
}
