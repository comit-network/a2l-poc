use crate::secp256k1;
pub use bitcoin::Transaction;
use std::str::FromStr;

const DESCRIPTOR_TEMPLATE: &'static str = "c:and_v(vc:pk(X_t),pk(X_r))";

pub fn make_fund_output(
    value: u64,
    X_t: &secp256k1::PublicKey,
    X_r: &secp256k1::PublicKey,
) -> bitcoin::TxOut {
    let X_t = format!("{:x}", X_t);
    let X_r = format!("{:x}", X_r);

    let descriptor = DESCRIPTOR_TEMPLATE
        .replace("X_t", &X_t)
        .replace("X_r", &X_r);
    let descriptor = miniscript::Descriptor::<bitcoin::PublicKey>::from_str(&descriptor)
        .expect("a valid descriptor");

    bitcoin::TxOut {
        value,
        script_pubkey: descriptor.script_pubkey(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn compile_policy() {
        let policy =
            miniscript::policy::Concrete::<String>::from_str("and(pk(X_t),pk(X_r))").unwrap();

        let miniscript = policy.compile().unwrap();

        let descriptor = format!("{}", miniscript);

        assert_eq!(descriptor, DESCRIPTOR_TEMPLATE)
    }

    fn compressed_public_key(
    ) -> impl Strategy<Value = Result<secp256k1::PublicKey, secp256k1::Error>> {
        "02[0-9a-f]{64}".prop_map(|hex| secp256k1::PublicKey::from_str(&hex))
    }

    proptest! {
        #[test]
        fn any_two_public_keys_yield_a_valid_descriptor(value: u64, X_t in compressed_public_key(), X_r in compressed_public_key()) {
            let (X_t, X_r) = match (X_t, X_r) {
                (Ok(X_t), Ok(X_r)) => (X_t, X_r),
                _ => return Err(TestCaseError::Reject("generated invalid public key".into()))
            };

            make_fund_output(value, &X_t, &X_r)
        }
    }
}
