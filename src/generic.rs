use aes::cipher::{KeyIvInit as _, StreamCipher};
use ctr::Ctr64LE;
use hkdf::HkdfExtract;
use hmac::{Hmac, Mac as _};
use pqcrypto::{
    kem::kyber768,
    sign::dilithium3,
    traits::{
        kem::{Ciphertext, PublicKey as _, SharedSecret},
        sign::{DetachedSignature, PublicKey as _},
    },
};
use sha2::Sha256;

use crate::*;

pub fn signcrypt(sender: &PrivateKey, receiver: &PublicKey, m: &[u8]) -> Vec<u8> {
    // Bind the parties' identities.
    let mut hkdf = HkdfExtract::<Sha256>::new(None);
    hkdf.input_ikm(sender.public_key.ek.as_bytes());
    hkdf.input_ikm(sender.public_key.vk.as_bytes());
    hkdf.input_ikm(receiver.ek.as_bytes());
    hkdf.input_ikm(receiver.vk.as_bytes());

    // Encapsulate a key.
    let (k0, c0) = kyber768::encapsulate(&receiver.ek);
    hkdf.input_ikm(c0.as_bytes());
    hkdf.input_ikm(k0.as_bytes());

    // Derive two keys.
    let (_, prk) = hkdf.finalize();
    let (mut k1, mut k2) = ([0u8; 16], [0u8; 16]);
    prk.expand(b"confidentiality", &mut k1).expect("should expand successfully");
    prk.expand(b"authenticity", &mut k2).expect("should expand successfully");

    // Encrypt the message.
    let mut cipher = Ctr64LE::<aes::Aes128>::new(&k1.into(), &[0u8; 16].into());
    let mut c1 = m.to_vec();
    cipher.apply_keystream(&mut c1);

    // Calculate an HMAC of the ciphertext.
    let mut hmac = Hmac::<Sha256>::new_from_slice(&k2).expect("should create an HMAC");
    hmac.update(&c1);
    let mac = hmac.finalize().into_bytes();

    // Sign the MAC with the sender's signing key.
    let mut c2 = dilithium3::detached_sign(&mac, &sender.sk).as_bytes().to_vec();

    // Encrypt the signature.
    cipher.apply_keystream(&mut c2);

    // Return the encapsulated key, encrypted message, and encrypted signature.
    [c0.as_bytes(), &c1, &c2].concat()
}

pub fn unsigncrypt(receiver: &PrivateKey, sender: &PublicKey, c: &[u8]) -> Option<Vec<u8>> {
    // Bind the parties' identities.
    let mut hkdf = HkdfExtract::<Sha256>::new(None);
    hkdf.input_ikm(sender.ek.as_bytes());
    hkdf.input_ikm(sender.vk.as_bytes());
    hkdf.input_ikm(receiver.public_key.ek.as_bytes());
    hkdf.input_ikm(receiver.public_key.vk.as_bytes());

    // Create a mutable copy of the ciphertext and split it up.
    let mut out = c.to_vec();
    let (c0, c1) = out.split_at_mut(kyber768::ciphertext_bytes());
    let (c1, c2) = c1.split_at_mut(c1.len() - dilithium3::signature_bytes());

    // Decapsulate the shared secret with the receiver's decryption key and mix in the shared
    // secret.
    let en = kyber768::Ciphertext::from_bytes(c0).ok()?;
    let k0 = kyber768::decapsulate(&en, &receiver.dk);
    hkdf.input_ikm(en.as_bytes());
    hkdf.input_ikm(k0.as_bytes());

    // Derive two keys.
    let (_, prk) = hkdf.finalize();
    let (mut k1, mut k2) = ([0u8; 16], [0u8; 16]);
    prk.expand(b"confidentiality", &mut k1).expect("should expand successfully");
    prk.expand(b"authenticity", &mut k2).expect("should expand successfully");

    // Calculate an HMAC of the ciphertext.
    let mut hmac = Hmac::<Sha256>::new_from_slice(&k2).expect("should create an HMAC");
    hmac.update(c1);
    let mac = hmac.finalize().into_bytes();

    // Decrypt the message.
    let mut cipher = Ctr64LE::<aes::Aes128>::new(&k1.into(), &[0u8; 16].into());
    cipher.apply_keystream(c1);

    // Decrypt the signature.
    cipher.apply_keystream(c2);

    let sig = dilithium3::DetachedSignature::from_bytes(c2).ok()?;
    dilithium3::verify_detached_signature(&sig, &mac, &sender.vk).is_ok().then(|| c1.to_vec())
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
