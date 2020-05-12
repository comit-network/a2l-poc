//! Implementation of Pointcheval-Sanders signature scheme for Pedersen Commitments
//! As described in https://eprint.iacr.org/2015/525.pdf

use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, Scalar};
use rand::RngCore;

/////////////////////////
// Pedersen Commitment //
/////////////////////////

pub fn commit(G: &G1Affine, H: &G1Affine, m: &Scalar) -> (G1Affine, Scalar) {
    let r = random_scalar();
    ((G * r + H * m).into(), r)
}

/////////////////////////
// Pointcheval Sanders //
/////////////////////////

#[derive(Debug, Clone, PartialEq)]
pub struct PublicKey {
    pub Y1: G1Affine,
    pub X2: G2Affine,
    pub Y2: G2Affine,
}

impl PublicKey {
    pub fn as_tuple(&self) -> (&G1Affine, &G2Affine, &G2Affine) {
        (&self.Y1, &self.X2, &self.Y2)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeyPair {
    pub secret_key: G1Affine,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BlindedSignature {
    pub sigmaprime1: G1Affine,
    pub sigmaprime2: G1Affine,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    pub sigma1: G1Affine,
    pub sigma2: G1Affine,
}

fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut bytes[..]);
    Scalar::from_bytes_wide(&bytes)
}

pub fn keygen() -> KeyPair {
    let (x, y) = (random_scalar(), random_scalar());
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

pub fn sign(keypair: &KeyPair, commitment: &G1Affine) -> BlindedSignature {
    let X1 = &keypair.secret_key;
    let G1 = G1Affine::generator();
    let u = random_scalar();
    let C: G1Projective = commitment.clone().into();
    let sigmaprime1 = &G1 * &u;
    let sigmaprime2 = &(X1 + &C) * &u;

    BlindedSignature {
        sigmaprime1: sigmaprime1.into(),
        sigmaprime2: sigmaprime2.into(),
    }
}

pub fn unblind(blinded: BlindedSignature, pedersen_blinding: Scalar) -> Signature {
    let r = &pedersen_blinding;

    let sigma1 = blinded.sigmaprime1;
    let sigma2 = &blinded.sigmaprime2 + (-sigma1 * r);

    Signature {
        sigma1,
        sigma2: sigma2.into(),
    }
}

#[must_use]
pub fn verify(public_key: &PublicKey, message: &Scalar, signature: &Signature) -> bool {
    if signature.sigma1.is_identity().into() {
        return false;
    }
    let G2 = G2Affine::generator();
    let (_, X2, Y2) = public_key.as_tuple();
    pairing(&signature.sigma1, &(X2 + Y2 * message).into()) == pairing(&signature.sigma2, &G2)
}

#[must_use]
pub fn randomize(signature: &Signature) -> Signature {
    let random = random_scalar();
    Signature {
        sigma1: (signature.sigma1 * &random).into(),
        sigma2: (signature.sigma2 * &random).into(),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn pointcheval_sanders_end_to_end() {
        let keypair = keygen();
        let message = random_scalar();
        let (commitment, blinding) =
            commit(&G1Affine::generator(), &keypair.public_key.Y1, &message);
        let blinded_sig = sign(&keypair, &commitment);
        let sig = unblind(blinded_sig, blinding);
        assert!(
            verify(&keypair.public_key, &message, &sig),
            "unblinded signature verifies"
        );

        let randomized = randomize(&sig);

        assert_ne!(randomized, sig, "randomized signature is different");

        assert!(
            verify(&keypair.public_key, &message, &randomized),
            "randomized signature verifies"
        );
    }
}
