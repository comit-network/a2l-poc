use crate::secp256k1;

use class_group::primitives::cl_dl::{self};
use class_group::BinaryQF;
use curv::arithmetic::traits::Converter;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use curv::BigInt;
use curv::GE;
use std::ops::Mul;

static CLASS_GROUP: conquer_once::Lazy<cl_dl::ClassGroup> =
    conquer_once::Lazy::new(|| cl_dl::ClassGroup::new(&1234));

// TODO: Cannot use a static class group because PARI segfaults :(
// static CLASS_GROUP: conquer_once::Lazy<cl_dl::ClassGroup> = conquer_once::Lazy::new(|| {
//     cl_dl::ClassGroup {
//         delta_k: BigInt::from_hex("-d1f7b908bda125c9f7d4b2790282182db6ab5742112061cc8d72dd23de3d44bcdf186010430ceada6350bb6b277b54b765941dfbdd57273ebcfee36f52d4317c31b936bd9c094269a885ee2c851cc73bc450c4bb8d76335f850dfa693b568ee117e086aaed24dcab8a8f9d7dd59654c7cf71661f8da900f9a8c5f083e239691d2d54fe2bace3d6ab8b8f5320047a35fcb5786ccd44058dc40412ec1fb462321d891e7c58d879b3943"),
//         delta_q: BigInt::from_hex("-d1f7b908bda125c9f7d4b2790282182ba107431b84bb0f68f1a10398ecec061c7dc83e20e1e78550cbd38c1198f5ff5fbb2d48259d0a0999ec038d95bde53611eedd89e85769b47fef9b77275c10be33f4a3471e5112ea573944fa89a8075b76faa27a24ed33a19614dfee187bbb5fc85741d6e450daa6f5bf52d354f34aa6149f1a051cd33402e0ccd39ef18c9c01f790fb40140504f2e0c986f11efa24ea43671fb7138348579984aaf24e31e5a68e7f8f998c7b13e7127fd3b6b156b5b00199dbc80102754f6cca5ab8d12e156704048a0a11eecc22d2ff9c576c43e8a1c4d9216d20108e890c3"),
//         gq: BinaryQF {
//             a: BigInt::from_hex("f20765baecfb8a1b19be7760ad748d3f456c418a4d6b9b432a8470604eaf5b1349df3b80b4ee179277b2a1d98d5fe1d1ee72f9fa86fb27e80ef370fe39a4f0d9b7c29dc1bcf2a0569de7857d3c187e0cd9977ef0582c86e7ad6b8d464870861eb49e99b6895642a965edb8a5d6f0f7ff14c005d9"),
//             b: BigInt::from_hex("394b071a96868e58bc6c3883f1c2b1b4705c170f1cbe93c8bb987ff55947ae9c380b9f393d406483f9e76c78777dc97d79ce84d6e6f26af956d48b019716d1610bcd1c2d257571bb75c446b14d167d0784a36775b29af868b0ac3075f57c2bc21afccc5ac09f0f46810d4421bea0eaf3bf1de9291"),
//             c: BigInt::from_hex("a5a17d7f257f75365e49034bcf4609a98096ddcd640ef671a81d60de2a303953bb3424772de99819b1ea5c1cc8303c820bdb58787a9bdf17b31a4ba9ad2425e5a79b90ed47dbdcab26e531cd376216546432fa988eed2a61b064fe52169da4b07c1a5576a07e2e4d72a20cfcda5e05344bbe0af1")
//         },
//         stilde: BigInt::from_hex("867cdc4399044c2e9fcc44892bb12ad5360a5ff21b1ce59bf6dd1c40cfbc24564bda51571949b97e7651d12b85a690bb00976995121f96d58952b7a26d88323fc34b3f30aadfc33446b221e42bfbeb11e2d1b0b4d48")
//     }
// });

#[derive(Debug, Clone)]
pub struct PublicKey {
    inner: BinaryQF,
}

#[derive(Debug, Clone)]
pub struct KeyPair {
    inner: cl_dl::KeyPair,
}

impl KeyPair {
    pub fn to_pk(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.public_key.clone(),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, PartialEq)]
pub struct Ciphertext {
    inner: cl_dl::Ciphertext,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Proof {
    inner: cl_dl::CLDLProof,
}

pub fn keygen() -> KeyPair {
    KeyPair {
        inner: cl_dl::KeyPair::random(&CLASS_GROUP),
    }
}

pub fn encrypt(public_key: &PublicKey, witness: &secp256k1::KeyPair) -> (Ciphertext, Proof) {
    let x = ECScalar::from(&BigInt::from(witness.to_sk().serialize().as_ref()));
    let X = GE::from_bytes(&witness.to_pk().serialize()[1..]).unwrap();

    let (ciphertext, proof) = cl_dl::verifiably_encrypt(&CLASS_GROUP, &public_key.inner, (&x, &X));

    (Ciphertext { inner: ciphertext }, Proof { inner: proof })
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

    let encrypts = GE::from_bytes(&pk.serialize()[1..]).unwrap();

    proof
        .inner
        .verify(
            &CLASS_GROUP,
            &public_key.inner,
            &ciphertext.inner,
            &encrypts,
        )
        .map_err(|_| VerificationError)?;

    Ok(())
}

impl Mul<&secp256k1::KeyPair> for &Ciphertext {
    type Output = Ciphertext;
    fn mul(self, rhs: &secp256k1::KeyPair) -> Self::Output {
        Ciphertext {
            inner: cl_dl::eval_scal(&self.inner, &BigInt::from(&rhs.as_sk().serialize()[..])),
        }
    }
}

pub fn decrypt(keypair: &KeyPair, ciphertext: &Ciphertext) -> secp256k1::SecretKey {
    let fe =
        cl_dl::decrypt(&CLASS_GROUP, &keypair.inner.secret_key, &ciphertext.inner).to_big_int();
    let bytes = BigInt::to_vec(&fe);

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
        let kp = keygen();
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

    #[test]
    fn make_class_group() {
        let class_group =
            cl_dl::ClassGroup::new_from_setup(&1348, &BigInt::from(b"A2L-POC".as_ref()));

        let delta_k = class_group.delta_k.to_hex();
        let delta_q = class_group.delta_q.to_hex();
        let stilde = class_group.stilde.to_hex();
        let gqa = class_group.gq.a.to_hex();
        let gqb = class_group.gq.b.to_hex();
        let gqc = class_group.gq.c.to_hex();

        let reconstructed = cl_dl::ClassGroup {
            delta_k: BigInt::from_hex(&delta_k),
            delta_q: BigInt::from_hex(&delta_q),
            gq: BinaryQF {
                a: BigInt::from_hex(&gqa),
                b: BigInt::from_hex(&gqb),
                c: BigInt::from_hex(&gqc),
            },
            stilde: BigInt::from_hex(&stilde),
        };

        assert_eq!(class_group.delta_q, reconstructed.delta_q);
        assert_eq!(class_group.delta_k, reconstructed.delta_k);
        assert_eq!(class_group.stilde, reconstructed.stilde);
        assert_eq!(class_group.gq, reconstructed.gq);

        println!("delta_k = {}", delta_k);
        println!("delta_q = {}", delta_q);
        println!("stilde = {}", stilde);
        println!("gqa = {}", gqa);
        println!("gqb = {}", gqc);
        println!("gqc = {}", gqb);
    }
}
