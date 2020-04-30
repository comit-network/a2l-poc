pub mod secp256k1_secret_key {
    pub fn serialize<S>(secret_key: &secp256k1::SecretKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&secret_key.serialize())
    }
}

pub mod secp256k1_scalar {
    pub fn serialize<S>(scalar: &secp256k1::curve::Scalar, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(scalar.b32().as_ref())
    }
}

pub mod secp256k1_public_key {
    pub fn serialize<S>(public_key: &secp256k1::PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&public_key.serialize_compressed())
    }
}

pub mod secp256k1_signature {
    pub fn serialize<S>(signature: &secp256k1::Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&signature.serialize())
    }
}
