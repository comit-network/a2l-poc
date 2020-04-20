use crate::dleq;
use crate::secp256k1::Affine;
use crate::secp256k1::SecretKey;
use crate::secp256k1::ToMessage;
use crate::secp256k1::XCoor;
use crate::secp256k1::G;
use crate::secp256k1::{KeyPair, Scalar};
use crate::secp256k1::{PublicKey, Signature};
use std::convert::{TryFrom, TryInto};

#[derive(Debug)]
pub struct EncryptedSignature {
    R: PublicKey,
    R_hat: PublicKey,
    s_hat: SecretKey,
    proof: dleq::Proof,
}

pub fn encsign<M, S: AsRef<SecretKey>, R: rand::Rng>(
    message: M,
    x: &S,
    Y: &PublicKey,
    rng: &mut R,
) -> EncryptedSignature
where
    M: ToMessage,
{
    let r = SecretKey::random(rng);

    let R_hat = {
        let mut R_hat = G.clone();
        R_hat.tweak_mul_assign(&r).unwrap();

        R_hat
    };

    let R = {
        let mut R = Y.clone();
        R.tweak_mul_assign(&r).unwrap();

        R
    };

    let proof = dleq::prove(rng, &*G, &R_hat, &Y, &R, r.clone().into());

    let s_hat = {
        let R_x = SecretKey::parse(&R.x_coor()).unwrap();

        let mut s_hat = R_x;
        s_hat.tweak_mul_assign(x.as_ref()).unwrap();
        s_hat
            .tweak_add_assign(&SecretKey::parse(&message.to_message()).unwrap())
            .unwrap();

        let r_inv = r.inv();

        s_hat.tweak_mul_assign(&r_inv).unwrap();

        s_hat
    };

    EncryptedSignature {
        R,
        R_hat,
        s_hat,
        proof,
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid encrypted signature")]
pub struct InvalidEncryptedSignature;

pub fn encverify(
    X: &PublicKey,
    Y: &PublicKey,
    message_hash: &[u8; 32],
    EncryptedSignature {
        R,
        R_hat,
        s_hat,
        proof,
    }: &EncryptedSignature,
) -> anyhow::Result<()> {
    //TODO: check that s_hat is not 0 -- it will cause a panic
    dleq::verify(&G, R_hat, Y, R, proof)?;

    //TODO: Don't panic on something that can be provided by a malicious party
    // ::parse(0) panics
    let R_x = SecretKey::parse(&R.x_coor()).unwrap();

    let message_hash = SecretKey::parse(message_hash).unwrap();

    let s_hat_inv = s_hat.inv();

    let U0 = {
        let mut u0 = message_hash;
        u0.tweak_mul_assign(&s_hat_inv).unwrap();

        let mut U0 = G.clone();
        U0.tweak_mul_assign(&u0).unwrap();
        U0
    };

    let U1 = {
        let mut u1 = R_x;
        u1.tweak_mul_assign(&s_hat_inv).unwrap();
        let mut U1 = X.clone();
        U1.tweak_mul_assign(&u1).unwrap();
        U1
    };

    let R_hat_candidate = PublicKey::combine(&[U0, U1]).unwrap();

    if &R_hat_candidate != R_hat {
        return Err(InvalidEncryptedSignature.into());
    }

    Ok(())
}

pub fn decsig<S: AsRef<SecretKey>>(
    y: &S,
    EncryptedSignature { R, s_hat, .. }: &EncryptedSignature,
) -> Signature {
    let s = {
        let y_inv = y.as_ref().inv();

        let mut s = s_hat.clone();
        s.tweak_mul_assign(&y_inv).unwrap();
        s
    };

    let R_x = R.x_coor();

    Signature {
        s: s.into(),
        r: SecretKey::parse(&R_x).unwrap().into(),
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryKey {
    Y: PublicKey,
    s_hat: Scalar,
}

pub fn reckey(Y: &PublicKey, EncryptedSignature { s_hat, .. }: &EncryptedSignature) -> RecoveryKey {
    RecoveryKey {
        Y: Y.clone(),
        s_hat: s_hat.clone().into(),
    }
}

pub fn recover(
    Signature { s, .. }: &Signature,
    RecoveryKey { Y, s_hat }: &RecoveryKey,
) -> anyhow::Result<KeyPair> {
    let y_macron = {
        let s_inv = s.inv();
        let s_hat = s_hat.clone();

        s_hat * s_inv
    };

    let Gy_macron: Affine = {
        let mut Gy_macron = G.clone();
        Gy_macron.tweak_mul_assign(&y_macron.clone().try_into().unwrap())?;

        Gy_macron.into()
    };
    let Y: Affine = Y.clone().into();

    if Gy_macron == Y {
        Ok(KeyPair::try_from(y_macron)?)
    } else if Gy_macron == Y.neg() {
        Ok(KeyPair::try_from(-y_macron)?)
    } else {
        Err(anyhow::anyhow!("recovery key does not match signature"))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use secp256k1::Message;

    impl ToMessage for [u8; 32] {
        fn to_message(&self) -> [u8; 32] {
            *self
        }
    }

    #[test]
    fn encsign_and_encverify() {
        let x = KeyPair::random_from_thread_rng();
        let y = KeyPair::random_from_thread_rng();
        let message = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

        let encsig = encsign(*message, &x, &y.to_pk(), &mut rand::thread_rng());

        encverify(&x.to_pk(), &y.to_pk(), message, &encsig).unwrap();
    }

    #[test]
    fn ecdsa_encsign_and_decsig() {
        let x = KeyPair::random_from_thread_rng();
        let y = KeyPair::random_from_thread_rng();

        let message = b"mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";

        let encsig = encsign(*message, &x, &y.to_pk(), &mut rand::thread_rng());

        let sig = decsig(&y, &encsig);

        assert!(::secp256k1::verify(
            &Message::parse(message),
            &sig,
            &x.to_pk()
        ))
    }

    #[test]
    fn recover_key_from_decrypted_signature() {
        let x = KeyPair::random_from_thread_rng();
        let y = KeyPair::random_from_thread_rng();

        let message = b"mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";

        let encsig = encsign(*message, &x, &y.to_pk(), &mut rand::thread_rng());
        let sig = decsig(&y, &encsig);

        let rec_key = reckey(&y.to_pk(), &encsig);
        let y_tag = recover(&sig, &rec_key).unwrap();

        assert_eq!(y, y_tag);
    }
}
