use lockstitch::Protocol;
use pqcrypto::{
    kem::kyber768,
    sign::dilithium3,
    traits::{
        kem::{Ciphertext, PublicKey as _, SharedSecret},
        sign::{DetachedSignature, PublicKey as _},
    },
};

use crate::*;

pub fn signcrypt(sender: &PrivateKey, receiver: &PublicKey, m: &[u8]) -> Vec<u8> {
    // Initialize a new protocol.
    let mut proto = Protocol::new("pqc-signcryption");

    // Mix in the sender's encryption and verification keys, binding the output to the sender's
    // identity.
    proto.mix("sender-ek", sender.public_key.ek.as_bytes());
    proto.mix("sender-vk", sender.public_key.vk.as_bytes());

    // Mix in the receiver's encryption and verification keys, binding the output to the receiver's
    // identity.
    proto.mix("receiver-ek", receiver.ek.as_bytes());
    proto.mix("receiver-vk", receiver.vk.as_bytes());

    // Encapsulate a random key with the receiver's encryption key and mix in the shared secret.
    let (k, c0) = kyber768::encapsulate(&receiver.ek);
    proto.mix("encapsulated-key", c0.as_bytes());
    proto.mix("shared-secret", k.as_bytes());

    // Encrypt the message, making future protocol outputs dependent on it.
    let mut c1 = m.to_vec();
    proto.encrypt("message", &mut c1);

    // Derive a challenge value to be signed.
    let challenge = proto.derive_array::<32>("challenge");

    // Sign the challenge value with the sender's signing key.
    let mut c2 = dilithium3::detached_sign(&challenge, &sender.sk).as_bytes().to_vec();

    // Encrypt the signature.
    proto.encrypt("signature", &mut c2);

    // Return the encapsulated key, encrypted message, and encrypted signature.
    [c0.as_bytes(), &c1, &c2].concat()
}

pub fn unsigncrypt(receiver: &PrivateKey, sender: &PublicKey, c: &[u8]) -> Option<Vec<u8>> {
    // Initialize a new protocol.
    let mut proto = Protocol::new("pqc-signcryption");

    // Mix in the sender's encryption and verification keys, binding the output to the sender's
    // identity.
    proto.mix("sender-ek", sender.ek.as_bytes());
    proto.mix("sender-vk", sender.vk.as_bytes());

    // Mix in the receiver's encryption and verification keys, binding the output to the receiver's
    // identity.
    proto.mix("receiver-ek", receiver.public_key.ek.as_bytes());
    proto.mix("receiver-vk", receiver.public_key.vk.as_bytes());

    // Create a mutable copy of the ciphertext and split it up.
    let mut c = c.to_vec();
    let (c0, c1) = c.split_at_mut(kyber768::ciphertext_bytes());
    let (c1, c2) = c1.split_at_mut(c1.len() - dilithium3::signature_bytes());

    // Decapsulate the shared secret with the receiver's decryption key and mix in the shared
    // secret.
    let k = kyber768::decapsulate(&kyber768::Ciphertext::from_bytes(c0).ok()?, &receiver.dk);
    proto.mix("encapsulated-key", c0);
    proto.mix("shared-secret", k.as_bytes());

    // Decrypt the message in place.
    proto.decrypt("message", c1);

    // Derive a challenge value to check the signature.
    let challenge = proto.derive_array::<32>("challenge");

    // Decrypt the signature.
    proto.decrypt("signature", c2);

    // Verify the signature, returning the plaintext if valid.
    let sig = dilithium3::DetachedSignature::from_bytes(c2).ok()?;
    dilithium3::verify_detached_signature(&sig, &challenge, &sender.vk).is_ok().then(|| c1.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let (a, b) = (keypair(), keypair());
        let c = signcrypt(&a, &b.public_key, b"this is a message");
        let p = unsigncrypt(&b, &a.public_key, &c);
        assert_eq!(p, Some(b"this is a message".to_vec()));
    }

    #[test]
    fn bad_sender() {
        let (a, b) = (keypair(), keypair());
        let c = signcrypt(&a, &b.public_key, b"this is a message");
        let p = unsigncrypt(&b, &b.public_key, &c);
        assert_eq!(p, None);
    }

    #[test]
    fn bad_receiver() {
        let (a, b) = (keypair(), keypair());
        let c = signcrypt(&a, &b.public_key, b"this is a message");
        let p = unsigncrypt(&a, &a.public_key, &c);
        assert_eq!(p, None);
    }

    #[test]
    fn bad_encapsulated_key() {
        let (a, b) = (keypair(), keypair());
        let mut c = signcrypt(&a, &b.public_key, b"this is a message");
        c[0] ^= 1;
        let p = unsigncrypt(&b, &a.public_key, &c);
        assert_eq!(p, None);
    }

    #[test]
    fn bad_message() {
        let (a, b) = (keypair(), keypair());
        let mut c = signcrypt(&a, &b.public_key, b"this is a message");
        c[kyber768::ciphertext_bytes() + 1] ^= 1;
        let p = unsigncrypt(&b, &a.public_key, &c);
        assert_eq!(p, None);
    }

    #[test]
    fn bad_sig() {
        let (a, b) = (keypair(), keypair());
        let mut c = signcrypt(&a, &b.public_key, b"this is a message");
        *c.last_mut().expect("should not be empty") ^= 1;
        let p = unsigncrypt(&b, &a.public_key, &c);
        assert_eq!(p, None);
    }
}
