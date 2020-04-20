use secp256k1::curve::AFFINE_G;
use secp256k1::PublicKey;

pub static G: conquer_once::Lazy<PublicKey> = conquer_once::Lazy::new(|| {
    PublicKey::parse_slice(&[AFFINE_G.x.b32(), AFFINE_G.y.b32()].concat(), None).unwrap()
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256k1::keypair::XCoor;
    use secp256k1::curve::Affine;

    #[test]
    fn big_G_eqauls_affine_G() {
        let generator = G.clone();

        let affine: Affine = generator.into();

        assert_eq!(affine, AFFINE_G);
    }

    #[test]
    fn generators_are_equal() {
        assert_eq!(G.x_coor(), bitcoin::secp256k1::constants::GENERATOR_X)
    }
}
