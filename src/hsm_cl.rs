use crate::secp256k1;

use class_group::primitives::cl_dl_lcm::{CLDLProofPublicSetup, Witness, HSMCL, PK};
use curv::arithmetic::traits::Converter;
use curv::arithmetic::traits::Samplable;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use curv::BigInt;
use curv::FE;
use curv::GE;

pub use class_group::primitives::cl_dl_lcm::{self, ProofError};
use std::ops::Mul;

#[derive(Debug, Clone)]
pub struct PublicKey {
    inner: PK,
    public_setup: BigInt,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq)]
pub struct Ciphertext(cl_dl_lcm::Ciphertext);

#[derive(Clone, Debug, serde::Serialize)]
pub struct Proof(CLDLProofPublicSetup);

#[derive(Clone, Debug)]
pub struct KeyPair {
    inner: HSMCL,
    public_setup: BigInt,
}

impl KeyPair {
    pub fn to_pk(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.pk.clone(),
            public_setup: self.public_setup.clone(),
        }
    }
}

pub fn keygen(public_setup: impl AsRef<[u8]>) -> KeyPair {
    let public_setup = BigInt::from(public_setup.as_ref());

    KeyPair {
        inner: HSMCL::keygen_with_setup(&FE::q(), &1348, &public_setup),
        public_setup,
    }
}

pub fn encrypt(public_key: &PublicKey, witness: &secp256k1::KeyPair) -> (Ciphertext, Proof) {
    let r = BigInt::sample_below(&(&public_key.inner.stilde * BigInt::from(2).pow(40)));
    let x = BigInt::from(witness.to_sk().serialize().as_ref());
    let ciphertext = HSMCL::encrypt_predefined_randomness(&public_key.inner, &x, &r);
    let pk_untagged_bytes = &witness.to_pk().serialize()[1..];
    let X = GE::from_bytes(pk_untagged_bytes).unwrap();

    let proof = Proof(CLDLProofPublicSetup::prove(
        Witness { x: &x, r },
        &public_key.inner,
        &ciphertext,
        &X,
    ));
    let ciphertext = Ciphertext(ciphertext);

    (ciphertext, proof)
}

#[derive(thiserror::Error, Debug)]
#[error("Failed to verify statement")]
pub struct VerificationError;

pub fn verify(
    public_key: &PublicKey,
    proof: &Proof,
    statement: (&Ciphertext, &secp256k1::PublicKey),
) -> Result<(), VerificationError> {
    let (ciphertext, pk) = statement;

    let pk_untagged_bytes = &pk.serialize()[1..];
    let encrypts = GE::from_bytes(pk_untagged_bytes).unwrap();
    proof
        .0
        .verify(
            &public_key.inner,
            &ciphertext.0,
            &encrypts,
            &public_key.public_setup,
        )
        .map_err(|_| VerificationError)?;

    Ok(())
}

impl Mul<&secp256k1::KeyPair> for &Ciphertext {
    type Output = Ciphertext;
    fn mul(self, rhs: &secp256k1::KeyPair) -> Self::Output {
        Ciphertext(HSMCL::eval_scal(
            &self.0,
            &BigInt::from(&rhs.as_sk().serialize()[..]),
        ))
    }
}

pub fn decrypt(keypair: &KeyPair, ciphertext: &Ciphertext) -> secp256k1::SecretKey {
    let bytes = BigInt::to_vec(&keypair.inner.decrypt(&ciphertext.0));

    // Note, if this isn't true then the problem should be solved at a lower level :^)
    debug_assert!(
        bytes.len() <= 32,
        "decrypted value must < 32 because it was derived from discrete log of something of order q"
    );

    let mut bytes_32 = [0u8; 32];
    // copy into the least significant bytes
    bytes_32[32 - bytes.len()..].copy_from_slice(&bytes[..]);

    secp256k1::SecretKey::parse(&bytes_32).unwrap()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::secp256k1::Scalar;

    #[test]
    fn end_to_end() {
        let public_setup = b"A2L-PoC";
        let kp = keygen(&public_setup);
        let public_key = kp.to_pk();
        let msg = crate::secp256k1::KeyPair::random(&mut rand::thread_rng());

        let (ciphertext, proof) = encrypt(&public_key, &msg);

        assert!(verify(&public_key, &proof, (&ciphertext, &msg.to_pk())).is_ok());

        assert_eq!(
            decrypt(&kp, &ciphertext),
            msg.to_sk(),
            "decryption yields original encrypted message"
        );

        let blinding = crate::secp256k1::KeyPair::random(&mut rand::thread_rng());

        let blinded_ciphertext = &ciphertext * &blinding;

        assert_ne!(
            blinded_ciphertext, ciphertext,
            "ciphertexts should not be equal after mutation"
        );

        assert!(
            verify(&public_key, &proof, (&blinded_ciphertext, &msg.to_pk()),).is_err(),
            "proof should not longer work on mutated ciphertext"
        );

        let decrypted_blinded = decrypt(&kp, &blinded_ciphertext);

        assert_eq!(
            Into::<Scalar>::into(decrypted_blinded),
            Into::<Scalar>::into(blinding.to_sk()) * Into::<Scalar>::into(msg.to_sk()),
            "cipthertext multiplication produced same result as scalar multiplication"
        )
    }
}
