use class_group::primitives::cl_dl_lcm::{CLDLProofPublicSetup, Witness, HSMCL, PK};
use curv::arithmetic::traits::Converter;
use curv::arithmetic::traits::Samplable;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use curv::BigInt;
use curv::FE;
use curv::GE;

pub use class_group::primitives::cl_dl_lcm::Ciphertext;
pub type PublicKey = PK;

pub type Proof = CLDLProofPublicSetup;

#[derive(Clone, Debug)]
pub struct KeyPair(HSMCL);

impl KeyPair {
    pub fn public_key(&self) -> &PublicKey {
        &self.0.pk
    }

    pub fn gen(public_setup: &BigInt) -> Self {
        Self(HSMCL::keygen_with_setup(&FE::q(), &1348, &public_setup))
    }
}

pub fn encrypt(public_key: &PublicKey, message: &crate::secp256k1::KeyPair) -> (Ciphertext, Proof) {
    let r = BigInt::sample_below(&(&public_key.stilde * BigInt::from(2).pow(40)));
    let x = BigInt::from(message.secret_key().serialize().as_ref());
    let ciphertext = HSMCL::encrypt_predefined_randomness(&public_key, &x, &r);
    let pk_untagged_bytes = &message.public_key().serialize()[1..];
    let X = GE::from_bytes(pk_untagged_bytes).unwrap();

    let proof = CLDLProofPublicSetup::prove(Witness { x: &x, r }, public_key, &ciphertext, &X);

    (ciphertext, proof)
}

#[must_use]
pub fn verify(
    pk: &PublicKey,
    ciphertext: &Ciphertext,
    encrypts: &crate::secp256k1::PublicKey,
    proof: &Proof,
    public_setup: &BigInt,
) -> bool {
    let pk_untagged_bytes = &encrypts.serialize()[1..];
    let encrypts = GE::from_bytes(pk_untagged_bytes).unwrap();
    proof
        .verify(pk, ciphertext, &encrypts, &public_setup)
        .is_ok()
}

pub fn decrypt(keypair: &KeyPair, ciphertext: Ciphertext) -> secp256k1::curve::Scalar {
    let bytes = BigInt::to_vec(&keypair.0.decrypt(&ciphertext));

    // Note, if this isn't true then the problem should be solved at a lower level :^)
    debug_assert!(
        bytes.len() <= 32,
        "decrypted value must < 32 because it was derived from discrete log of something of order q"
    );

    let mut bytes_32 = [0u8; 32];
    // copy into the least significant bytes
    bytes_32[32 - bytes.len()..].copy_from_slice(&bytes[..]);

    let mut scalar = secp256k1::curve::Scalar::default();
    let overflow: bool = scalar.set_b32(&bytes_32).into();
    debug_assert!(
        !overflow,
        "this shouldn't overflow for the same reason as above"
    );
    scalar
}

pub fn multiply(ciphertext: &Ciphertext, sk: &secp256k1::SecretKey) -> Ciphertext {
    HSMCL::eval_scal(&ciphertext, &BigInt::from(&sk.serialize()[..]))
}

#[cfg(test)]
mod test {
    use super::*;
    use secp256k1::curve::Scalar;

    #[test]
    fn end_to_end() {
        let public_setup = BigInt::from(b"A2L-PoC".as_ref());
        let kp = KeyPair::gen(&public_setup);
        let public_key = kp.public_key();
        let msg = crate::secp256k1::KeyPair::random(&mut rand::thread_rng());

        let (ciphertext, proof) = encrypt(public_key, &msg);

        assert!(verify(
            public_key,
            &ciphertext,
            msg.public_key(),
            &proof,
            &public_setup
        ));

        assert_eq!(
            decrypt(&kp, ciphertext.clone()),
            msg.secret_key().clone().into(),
            "decryption yields original encrypted message"
        );

        let blinding = crate::secp256k1::KeyPair::random(&mut rand::thread_rng());

        let blinded_ciphertext = multiply(&ciphertext, blinding.secret_key());

        assert_ne!(
            blinded_ciphertext, ciphertext,
            "ciphertexts should not be equal after mutation"
        );

        assert!(
            !verify(
                public_key,
                &blinded_ciphertext,
                msg.public_key(),
                &proof,
                &public_setup
            ),
            "proof should not longer work on mutated ciphertext"
        );

        let decrypted_blinded = decrypt(&kp, blinded_ciphertext);

        assert_eq!(
            decrypted_blinded,
            Into::<Scalar>::into(blinding.secret_key().clone())
                * Into::<Scalar>::into(msg.secret_key().clone()),
            "cipthertext multiplication produced same result as scalar multiplication"
        )
    }
}
