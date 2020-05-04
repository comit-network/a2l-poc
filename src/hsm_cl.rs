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

#[derive(Debug)]
pub struct PublicKey {
    inner: PK,
    public_setup: BigInt,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Ciphertext(cl_dl_lcm::Ciphertext);

#[derive(Debug, serde::Serialize)]
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

pub trait Encrypt {
    fn encrypt(&self, witness: &secp256k1::KeyPair) -> (Ciphertext, Proof);
}

impl Encrypt for PublicKey {
    fn encrypt(&self, witness: &secp256k1::KeyPair) -> (Ciphertext, Proof) {
        let r = BigInt::sample_below(&(&self.inner.stilde * BigInt::from(2).pow(40)));
        let x = BigInt::from(witness.to_sk().serialize().as_ref());
        let ciphertext = HSMCL::encrypt_predefined_randomness(&self.inner, &x, &r);
        let pk_untagged_bytes = &witness.to_pk().serialize()[1..];
        let X = GE::from_bytes(pk_untagged_bytes).unwrap();

        let proof = Proof(CLDLProofPublicSetup::prove(
            Witness { x: &x, r },
            &self.inner,
            &ciphertext,
            &X,
        ));
        let ciphertext = Ciphertext(ciphertext);

        (ciphertext, proof)
    }
}

#[derive(thiserror::Error, Debug)]
#[error("Failed to verify statement")]
pub struct VerificationError;

pub trait Verify {
    fn verify(
        &self,
        proof: &Proof,
        statement: (&Ciphertext, &secp256k1::PublicKey),
    ) -> Result<(), VerificationError>;
}

impl Verify for PublicKey {
    fn verify(
        &self,
        proof: &Proof,
        statement: (&Ciphertext, &secp256k1::PublicKey),
    ) -> Result<(), VerificationError> {
        let (ciphertext, pk) = statement;

        let pk_untagged_bytes = &pk.serialize()[1..];
        let encrypts = GE::from_bytes(pk_untagged_bytes).unwrap();
        proof
            .0
            .verify(&self.inner, &ciphertext.0, &encrypts, &self.public_setup)
            .map_err(|_| VerificationError)?;

        Ok(())
    }
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

pub trait Decrypt {
    fn decrypt(&self, ciphertext: &Ciphertext) -> secp256k1::SecretKey;
}

impl Decrypt for KeyPair {
    fn decrypt(&self, ciphertext: &Ciphertext) -> secp256k1::SecretKey {
        let bytes = BigInt::to_vec(&self.inner.decrypt(&ciphertext.0));

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
}

// #[cfg(test)]
// mod test {
//     use super::*;
//     use secp256k1::curve::Scalar;

//     #[test]
//     fn end_to_end() {
//         let public_setup = BigInt::from(b"A2L-PoC".as_ref());
//         let kp = KeyPair::gen(&public_setup);
//         let public_key = kp.to_pk();
//         let msg = crate::secp256k1::KeyPair::random(&mut rand::thread_rng());

//         let (ciphertext, proof) = encrypt(public_key, &msg);

//         assert!(verify(
//             public_key,
//             &ciphertext,
//             msg.to_pk(),
//             &proof,
//             &public_setup
//         ));

//         assert_eq!(
//             decrypt(&kp, ciphertext.clone()),
//             msg.secret_key().clone().into(),
//             "decryption yields original encrypted message"
//         );

//         let blinding = crate::secp256k1::KeyPair::random(&mut rand::thread_rng());

//         let blinded_ciphertext = multiply(&ciphertext, blinding.secret_key());

//         assert_ne!(
//             blinded_ciphertext, ciphertext,
//             "ciphertexts should not be equal after mutation"
//         );

//         assert!(
//             !verify(
//                 public_key,
//                 &blinded_ciphertext,
//                 msg.to_pk(),
//                 &proof,
//                 &public_setup
//             ),
//             "proof should not longer work on mutated ciphertext"
//         );

//         let decrypted_blinded = decrypt(&kp, blinded_ciphertext);

//         assert_eq!(
//             decrypted_blinded,
//             Into::<Scalar>::into(blinding.secret_key().clone())
//                 * Into::<Scalar>::into(msg.secret_key().clone()),
//             "cipthertext multiplication produced same result as scalar multiplication"
//         )
//     }
// }
