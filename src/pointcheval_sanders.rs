//! Implementation of Pointcheval-Sanders signature scheme for Pedersen Commitments
//! As described in https://eprint.iacr.org/2015/525.pdf

use crate::random_bls12_381_scalar;
use bls12_381::{G1Affine, G1Projective, G2Affine, Gt, Scalar};
use rand::Rng;

#[derive(Debug, Clone, PartialEq)]
pub struct PublicKey {
    pub Y1: G1Affine,
    pub X2: G2Affine,
    pub Y2: G2Affine,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeyPair {
    pub secret_key: G1Affine,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Signature {
    #[serde(with = "crate::serde::bls12_381_g1affine")]
    pub sigma1: G1Affine,
    #[serde(with = "crate::serde::bls12_381_g1affine")]
    pub sigma2: G1Affine,
}

pub fn keygen(rng: &mut impl Rng) -> KeyPair {
    let (x, y) = (random_bls12_381_scalar(rng), random_bls12_381_scalar(rng));

    let (G1, G2) = (G1Affine::generator(), G2Affine::generator());
    let (X1, X2) = (&G1 * &x, &G2 * &x);
    let (Y1, Y2) = (&G1 * &y, &G2 * &y);

    KeyPair {
        secret_key: X1.into(),
        public_key: PublicKey {
            Y1: Y1.into(),
            X2: X2.into(),
            Y2: Y2.into(),
        },
    }
}

pub fn sign(keypair: &KeyPair, C: G1Affine, rng: &mut impl Rng) -> Signature {
    let X1 = &keypair.secret_key;
    let G1 = G1Affine::generator();
    let u = random_bls12_381_scalar(rng);
    let C = G1Projective::from(C);

    let sigmaprime1 = G1 * u;
    let sigmaprime2 = (X1 + C) * u;

    Signature {
        sigma1: sigmaprime1.into(),
        sigma2: sigmaprime2.into(),
    }
}

pub fn unblind(blinded: Signature, pedersen_blinding: Scalar) -> Signature {
    let r = &pedersen_blinding;

    let sigma1 = blinded.sigma1;
    let sigma2 = blinded.sigma2 + (-sigma1 * r);

    Signature {
        sigma1,
        sigma2: sigma2.into(),
    }
}

#[derive(Debug, thiserror::Error)]
#[error("signature is invalid")]
pub struct InvalidSignature;

pub fn verify(
    public_key: &PublicKey,
    m: &Scalar,
    signature: &Signature,
) -> Result<(), InvalidSignature> {
    // for the signature to be valid, sigma1 MUST NOT be equal to the identity element
    if signature.sigma1 == G1Affine::identity() {
        return Err(InvalidSignature);
    }

    let G2 = G2Affine::generator();
    let X2 = &public_key.X2;
    let Y2 = &public_key.Y2;
    let s1 = signature.sigma1;
    let s2 = signature.sigma2;

    if pairing(s1, X2 + Y2 * m) == pairing(s2, G2) {
        Ok(())
    } else {
        Err(InvalidSignature)
    }
}

/// Convenience pairing function that allows us to pass parameters without noise of parenthesis or `.into()` calls.
fn pairing<P, Q>(p: P, q: Q) -> Gt
where
    P: Into<G1Affine>,
    Q: Into<G2Affine>,
{
    bls12_381::pairing(&p.into(), &q.into())
}

pub fn randomize(signature: &Signature, rng: &mut impl Rng) -> Signature {
    let random = random_bls12_381_scalar(rng);

    Signature {
        sigma1: (signature.sigma1 * &random).into(),
        sigma2: (signature.sigma2 * &random).into(),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::pedersen::{commit, Decommitment};
    use rand::thread_rng;

    #[test]
    fn pointcheval_sanders_end_to_end() {
        let keypair = keygen(&mut thread_rng());
        let message = random_bls12_381_scalar(&mut thread_rng());

        let (commitment, Decommitment { r: blinding, .. }) = commit(
            &G1Affine::generator(),
            &keypair.public_key.Y1,
            &message,
            &mut rand::thread_rng(),
        );
        let blinded_sig = sign(&keypair, commitment, &mut thread_rng());
        let sig = unblind(blinded_sig, blinding);

        verify(&keypair.public_key, &message, &sig).expect("unblinded signature verifies");

        let randomized = randomize(&sig, &mut thread_rng());

        assert_ne!(randomized, sig, "randomized signature is different");

        verify(&keypair.public_key, &message, &randomized).expect("randomized signature verifies")
    }
}
