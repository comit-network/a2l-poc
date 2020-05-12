use bls12_381::{G1Affine, Scalar};
use rand::Rng;
use sha2::{Digest, Sha512};

pub type Commitment = G1Affine;
pub struct Decommitment {
    pub m: Scalar,
    pub r: Scalar,
}

pub fn commit(
    G: &G1Affine,
    H: &G1Affine,
    m: &Scalar,
    rng: &mut impl Rng,
) -> (Commitment, Decommitment) {
    let r = random_scalar(rng);
    let C = G * m + H * r;

    (C.into(), Decommitment { m: *m, r })
}

pub struct Proof {
    C_prime: G1Affine,
    u: Scalar,
    v: Scalar,
}

pub fn prove(
    G: &G1Affine,
    H: &G1Affine,
    C: &Commitment,
    Decommitment { m, r }: &Decommitment,
    rng: &mut impl Rng,
) -> Proof {
    let (y, s) = (random_scalar(rng), random_scalar(rng));

    let C_prime = G1Affine::from(G * y + H * s);
    let k = hash(C, &C_prime);
    let u = y + k * m;
    let v = s + k * r;

    Proof { C_prime, u, v }
}

#[derive(Debug, thiserror::Error, PartialEq)]
#[error("proof does not show knowledge of opening of commitment")]
pub struct ProofRejected;

pub fn verify(
    G: &G1Affine,
    H: &G1Affine,
    C: &Commitment,
    Proof { C_prime, u, v }: Proof,
) -> Result<(), ProofRejected> {
    let k = hash(C, &C_prime);

    if G * u + H * v == C_prime + C * k {
        Ok(())
    } else {
        Err(ProofRejected)
    }
}

fn hash(C: &G1Affine, C_prime: &G1Affine) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.input(C.to_uncompressed().as_ref());
    hasher.input(C_prime.to_uncompressed().as_ref());
    let k = hasher.result();

    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(k.as_slice());
    Scalar::from_bytes_wide(&bytes)
}

fn random_scalar(rng: &mut impl Rng) -> Scalar {
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes[..]);
    Scalar::from_bytes_wide(&bytes)
}

mod test {
    use super::*;

    #[test]
    fn pedersen_roundtrip() {
        let mut rng = rand::thread_rng();
        let G = G1Affine::from(G1Affine::generator() * random_scalar(&mut rng));
        let H = G1Affine::from(G1Affine::generator() * random_scalar(&mut rng));
        let m = random_scalar(&mut rng);

        let (C, D) = commit(&G, &H, &m, &mut rng);
        let proof = prove(&G, &H, &C, &D, &mut rng);
        let res = verify(&G, &H, &C, proof);

        assert_eq!(res, Ok(()));
    }
}
