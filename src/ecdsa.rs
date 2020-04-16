use crate::dleq;
use crate::secp256k1;
use crate::secp256k1::curve::Affine;
use crate::secp256k1::XCoor;
use std::convert::{TryFrom, TryInto};

#[derive(Debug)]
pub struct EncryptedSignature {
    R: secp256k1::PublicKey,
    R_hat: secp256k1::PublicKey,
    s_hat: secp256k1::SecretKey,
    proof: dleq::Proof,
}

pub fn encsign<R: rand::Rng>(
    rng: &mut R,
    x: &secp256k1::KeyPair,
    Y: &secp256k1::PublicKey,
    message_hash: &[u8; 32],
) -> EncryptedSignature {
    let r = secp256k1::SecretKey::random(rng);

    let R_hat = {
        let mut G = secp256k1::G.clone();
        G.tweak_mul_assign(&r).unwrap();

        G
    };

    let R = {
        let mut R = Y.clone();
        R.tweak_mul_assign(&r).unwrap();

        R
    };

    let proof = dleq::prove(rng, &*secp256k1::G, &R_hat, &Y, &R, r.clone().into());

    let s_hat = {
        let R_x = secp256k1::SecretKey::parse(&R.x_coor()).unwrap();

        let mut s_hat = R_x;
        s_hat.tweak_mul_assign(x.as_ref()).unwrap();
        s_hat
            .tweak_add_assign(&secp256k1::SecretKey::parse(&message_hash).unwrap())
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

#[derive(Debug, Clone)]
pub enum EncVerifyError {
    InvalidProof,
    Invalid,
}

pub fn encverify(
    X: &secp256k1::PublicKey,
    Y: &secp256k1::PublicKey,
    message_hash: &[u8; 32],
    EncryptedSignature {
        R,
        R_hat,
        s_hat,
        proof,
    }: &EncryptedSignature,
) -> Result<(), EncVerifyError> {
    //TODO: check that s_hat is not 0 -- it will cause a panic
    if !dleq::verify(&secp256k1::G, R_hat, Y, R, proof) {
        return Err(EncVerifyError::InvalidProof);
    }

    //TODO: Don't panic on something that can be provided by a malicious party
    // ::parse(0) panics
    let R_x = secp256k1::SecretKey::parse(&R.x_coor()).unwrap();

    let message_hash = secp256k1::SecretKey::parse(message_hash).unwrap();

    let s_hat_inv = s_hat.inv();

    let U0 = {
        let mut u0 = message_hash;
        u0.tweak_mul_assign(&s_hat_inv).unwrap();

        let mut U0 = secp256k1::G.clone();
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

    let R_hat_candidate = secp256k1::PublicKey::combine(&[U0, U1]).unwrap();

    if &R_hat_candidate == R_hat {
        Ok(())
    } else {
        Err(EncVerifyError::Invalid)
    }
}

pub fn decsig<S: AsRef<secp256k1::SecretKey>>(
    y: &S,
    EncryptedSignature { R, s_hat, .. }: &EncryptedSignature,
) -> secp256k1::Signature {
    let s = {
        let y_inv = y.as_ref().inv();

        let mut s = s_hat.clone();
        s.tweak_mul_assign(&y_inv).unwrap();
        s
    };

    let R_x = R.x_coor();

    secp256k1::Signature {
        s: s.into(),
        r: secp256k1::SecretKey::parse(&R_x).unwrap().into(),
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryKey {
    Y: secp256k1::PublicKey,
    s_hat: secp256k1::curve::Scalar,
}

pub fn reckey(
    Y: &secp256k1::PublicKey,
    EncryptedSignature { s_hat, .. }: &EncryptedSignature,
) -> RecoveryKey {
    RecoveryKey {
        Y: Y.clone(),
        s_hat: s_hat.clone().into(),
    }
}

pub fn recover(
    secp256k1::Signature { s, .. }: &secp256k1::Signature,
    RecoveryKey { Y, s_hat }: &RecoveryKey,
) -> anyhow::Result<secp256k1::KeyPair> {
    let y_macron = {
        let s_inv = s.inv();
        let s_hat = s_hat.clone();

        s_hat * s_inv
    };

    let Gy_macron: Affine = {
        let mut G = secp256k1::G.clone();
        G.tweak_mul_assign(&y_macron.clone().try_into().unwrap())?;

        G.into()
    };
    let Y: Affine = Y.clone().into();

    if Gy_macron == Y {
        Ok(secp256k1::KeyPair::try_from(y_macron)?)
    } else if Gy_macron == Y.neg() {
        Ok(secp256k1::KeyPair::try_from(-y_macron)?)
    } else {
        Err(anyhow::anyhow!("recovery key does not match signature"))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encsign_and_encverify() {
        let x = secp256k1::KeyPair::random_from_thread_rng();
        let y = secp256k1::KeyPair::random_from_thread_rng();
        let message_hash = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

        let enc_signature = encsign(&mut rand::thread_rng(), &x, &y.to_pk(), message_hash);

        encverify(&x.to_pk(), &y.to_pk(), message_hash, &enc_signature).unwrap();
    }

    #[test]
    fn ecdsa_encsign_and_decsig() {
        let x = secp256k1::KeyPair::random_from_thread_rng();
        let y = secp256k1::KeyPair::random_from_thread_rng();

        let message_hash = b"mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";
        let _message_hash = &secp256k1::Message::parse(message_hash);

        let encsig = encsign(&mut rand::thread_rng(), &x, &y.to_pk(), message_hash);

        let sig = decsig(&y, &encsig);

        assert!(secp256k1::verify(_message_hash, &sig, &x.to_pk()))
    }

    #[test]
    fn recover_key_from_decrypted_signature() {
        let x = secp256k1::KeyPair::random_from_thread_rng();
        let y = secp256k1::KeyPair::random_from_thread_rng();

        let message_hash = b"mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";

        let encsig = encsign(&mut rand::thread_rng(), &x, &y.to_pk(), message_hash);
        let sig = decsig(&y, &encsig);

        let rec_key = reckey(&y.to_pk(), &encsig);
        let y_tag = recover(&sig, &rec_key).unwrap();

        assert_eq!(y, y_tag);
    }
}
