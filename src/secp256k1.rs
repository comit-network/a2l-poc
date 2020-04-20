use bitcoin::hash_types::SigHash;
use bitcoin::hashes::Hash;
use secp256k1::curve::Scalar;
pub use secp256k1::*;
use std::convert::TryFrom;

pub static G: conquer_once::Lazy<PublicKey> = conquer_once::Lazy::new(|| {
    PublicKey::parse_slice(
        &[curve::AFFINE_G.x.b32(), curve::AFFINE_G.y.b32()].concat(),
        None,
    )
    .unwrap()
});

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

pub fn sign<S: AsRef<SecretKey>>(digest: SigHash, x: &S) -> Signature {
    let message = Message::parse(&digest.into_inner());
    let (signature, _) = ::secp256k1::sign(&message, x.as_ref());
    signature
}

#[derive(thiserror::Error, Debug)]
#[error("invalid signature")]
pub struct InvalidSignature;

pub fn verify(
    digest: SigHash,
    signature: &Signature,
    x: &PublicKey,
) -> Result<(), InvalidSignature> {
    let message = Message::parse(&digest.into_inner());
    let is_valid = ::secp256k1::verify(&message, signature, x);

    if is_valid {
        Ok(())
    } else {
        Err(InvalidSignature)
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

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::curve::Affine;

    #[test]
    fn big_G_eqauls_affine_G() {
        let generator = G.clone();

        let affine: Affine = generator.into();

        assert_eq!(affine, curve::AFFINE_G);
    }

    #[test]
    fn generators_are_equal() {
        assert_eq!(G.x_coor(), bitcoin::secp256k1::constants::GENERATOR_X)
    }
}
