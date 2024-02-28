//! An attempt at a post-quantum designated verifier signature scheme from standard algorithms. the
//! basic approach here is to sign a MAC of the message created with a key encapsulated for the
//! designated verifier instead of the message itself.

use hmac::{Hmac, Mac};
use pqcrypto::{
    kem::kyber768,
    sign::dilithium3,
    traits::{
        kem::{Ciphertext, SharedSecret},
        sign::DetachedSignature,
    },
};
use sha2::Sha256;

use crate::{PrivateKey, PublicKey};

pub fn sign(signer: &PrivateKey, verifier: &PublicKey, m: &[u8]) -> Vec<u8> {
    let (k, ct) = kyber768::encapsulate(&verifier.ek);
    let mac = Hmac::<Sha256>::new_from_slice(k.as_bytes())
        .expect("should create an HMAC")
        .chain_update(m)
        .finalize()
        .into_bytes();
    let sig = dilithium3::detached_sign(&mac, &signer.sk);
    [ct.as_bytes(), sig.as_bytes()].concat()
}

pub fn verify(verifier: &PrivateKey, signer: &PublicKey, m: &[u8], sig: &[u8]) -> bool {
    let (ct, sig) = sig.split_at(kyber768::ciphertext_bytes());
    let Ok(ct) = kyber768::Ciphertext::from_bytes(ct) else {
        return false;
    };
    let k = kyber768::decapsulate(&ct, &verifier.dk);
    let Ok(sig) = dilithium3::DetachedSignature::from_bytes(sig) else {
        return false;
    };
    let mac = Hmac::<Sha256>::new_from_slice(k.as_bytes())
        .expect("should create an HMAC")
        .chain_update(m)
        .finalize()
        .into_bytes();
    dilithium3::verify_detached_signature(&sig, &mac, &signer.vk).is_ok()
}

#[cfg(test)]
mod tests {
    use crate::keypair;

    use super::*;

    #[test]
    fn round_trip() {
        let (signer, verifier) = (keypair(), keypair());
        let sig = sign(&signer, &verifier.public_key, b"this is a message");
        assert!(verify(&verifier, &signer.public_key, b"this is a message", &sig));
        assert!(!verify(&signer, &signer.public_key, b"this is a message", &sig));
        assert!(!verify(&verifier, &signer.public_key, b"this is not a message", &sig));
        assert!(!verify(&verifier, &verifier.public_key, b"this is a message", &sig));
        assert!(!verify(
            &verifier,
            &verifier.public_key,
            b"this is a message",
            &vec![0u8; sig.len()]
        ));
    }
}
