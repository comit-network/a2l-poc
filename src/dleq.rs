use crate::secp256k1;
use sha2::Digest;
use sha2::Sha256;
use std::convert::TryInto;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Proof {
    #[serde(with = "crate::serde::secp256k1_scalar")]
    s: secp256k1::Scalar,
    #[serde(with = "crate::serde::secp256k1_scalar")]
    c: secp256k1::Scalar,
}

#[derive(Debug, thiserror::Error)]
#[error("discrete-log not equal")]
pub struct DiscreteLogNotEqual;

pub fn prove<R: rand::Rng>(
    rng: &mut R,
    G: &secp256k1::PublicKey,
    Gx: &secp256k1::PublicKey,
    H: &secp256k1::PublicKey,
    Hx: &secp256k1::PublicKey,
    x: secp256k1::Scalar,
) -> Proof {
    // NOTE: using rng for PoC and even early stage production but there
    // are more robust ways of doing this which include hashing secret
    // information along with randomness (see https://github.com/bitcoin/bips/pull/893/).
    let r = secp256k1::KeyPair::random(rng);
    let r = r.as_sk();

    // Gr
    let mut Gr = secp256k1::G.clone();
    Gr.tweak_mul_assign(r).unwrap();

    // Hr
    let mut Hr = H.clone();
    Hr.tweak_mul_assign(r).unwrap();

    // c = H(G | Gx | H | Hx | Gr | Hr)
    let mut hasher = Sha256::default();
    hasher.input(&G.serialize_compressed() as &[u8]);
    hasher.input(&Gx.serialize_compressed() as &[u8]);
    hasher.input(&H.serialize_compressed() as &[u8]);
    hasher.input(&Hx.serialize_compressed() as &[u8]);
    hasher.input(&Gr.serialize_compressed() as &[u8]);
    hasher.input(&Hr.serialize_compressed() as &[u8]);

    let r: secp256k1::Scalar = r.clone().into();

    let c: secp256k1::Scalar = secp256k1::SecretKey::parse_slice(&hasher.result()[..])
        .unwrap()
        .into();
    let s = r + c.clone() * x;

    Proof { s, c }
}

pub fn verify(
    G: &secp256k1::PublicKey,
    Gx: &secp256k1::PublicKey,
    H: &secp256k1::PublicKey,
    Hx: &secp256k1::PublicKey,
    proof: &Proof, // (s = r + cx, c)
) -> Result<(), DiscreteLogNotEqual> {
    let c_neg = -proof.c.clone();

    // Gr = Gs + (Gx * -c) = Gr + Gcx - Gcx
    let Gr = {
        let mut Gxc_neg = Gx.clone();
        // TODO: Don't panic on things controlled by adversary
        Gxc_neg
            .tweak_mul_assign(&c_neg.clone().try_into().unwrap())
            .unwrap();

        let mut Gs = G.clone();
        Gs.tweak_mul_assign(&proof.s.clone().try_into().unwrap())
            .unwrap();
        secp256k1::PublicKey::combine(&[Gxc_neg, Gs]).unwrap()
    };

    // Hr = Hs + (Hx * -c) = Hr + Hcx - Hcx
    let Hr = {
        let mut Hxc_neg = Hx.clone();
        Hxc_neg
            .tweak_mul_assign(&c_neg.try_into().unwrap())
            .unwrap();

        let mut Hs = H.clone();
        Hs.tweak_mul_assign(&proof.s.clone().try_into().unwrap())
            .unwrap();
        secp256k1::PublicKey::combine(&[Hxc_neg, Hs]).unwrap()
    };

    // c = H(G | Gx | H | Hx | Gr | Hr)
    let mut hasher = Sha256::default();
    hasher.input(&G.serialize_compressed() as &[u8]);
    hasher.input(&Gx.serialize_compressed() as &[u8]);
    hasher.input(&H.serialize_compressed() as &[u8]);
    hasher.input(&Hx.serialize_compressed() as &[u8]);
    hasher.input(&Gr.serialize_compressed() as &[u8]);
    hasher.input(&Hr.serialize_compressed() as &[u8]);
    let c = secp256k1::SecretKey::parse_slice(&hasher.result()[..])
        .unwrap()
        .into();

    // c == c'
    if proof.c != c {
        return Err(DiscreteLogNotEqual);
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::secp256k1;

    #[test]
    fn prove_and_verify() {
        let x_1 = secp256k1::KeyPair::random_from_thread_rng();
        let x_2 = secp256k1::KeyPair::random_from_thread_rng();

        let mut Gx = secp256k1::G.clone();
        Gx.tweak_mul_assign(x_1.as_sk()).unwrap();

        let mut H = secp256k1::G.clone();
        H.tweak_mul_assign(x_2.as_sk()).unwrap();

        let mut Hx = H.clone();
        Hx.tweak_mul_assign(x_1.as_sk()).unwrap();

        let proof = prove(
            &mut rand::thread_rng(),
            &secp256k1::G,
            &Gx,
            &H,
            &Hx,
            x_1.to_sk().into(),
        );

        verify(&secp256k1::G, &Gx, &H, &Hx, &proof).unwrap()
    }
}
