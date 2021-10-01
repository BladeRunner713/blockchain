use rand::{distributions::Alphanumeric, Rng};
use ring::signature::{Ed25519KeyPair, EdDSAParameters, KeyPair, Signature, VerificationAlgorithm};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Transaction {
    input: String,
    output: String,
}

/// Create digital signature of a transaction
pub fn sign(t: &Transaction, key: &Ed25519KeyPair) -> Signature {
    let string = t.input.to_string() + &t.output.to_string();
    let bytes = string.as_bytes();
    let signature = key.sign(bytes);
    return signature;
}

/// Verify digital signature of a transaction, using public key instead of secret key
pub fn verify(
    t: &Transaction,
    public_key: &<Ed25519KeyPair as KeyPair>::PublicKey,
    signature: &Signature,
) -> bool {
    let peer_public_key =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key);
    return peer_public_key
        .verify(
            (t.input.to_string() + &t.output.to_string()).as_bytes(),
            signature.as_ref(),
        )
        .is_ok();
}

#[cfg(any(test, test_utilities))]
mod tests {
    use super::*;
    use crate::crypto::key_pair;

    pub fn generate_random_transaction() -> Transaction {
        let input: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        let output: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        return Transaction { input, output };
    }

    #[test]
    fn sign_verify() {
        let t = generate_random_transaction();
        let key = key_pair::random();
        let signature = sign(&t, &key);
        assert!(verify(&t, &(key.public_key()), &signature));
    }
}
