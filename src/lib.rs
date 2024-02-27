use pqcrypto::{ kem::kyber768, sign::dilithium3};

pub mod generic;
pub mod protocol;

pub struct PublicKey {
    ek: kyber768::PublicKey,
    vk: dilithium3::PublicKey,
}

pub struct PrivateKey {
    dk: kyber768::SecretKey,
    sk: dilithium3::SecretKey,
    pub public_key: PublicKey,
}

pub fn keypair() -> PrivateKey {
    let (ek, dk) = kyber768::keypair();
    let (vk, sk) = dilithium3::keypair();
    PrivateKey { dk, sk, public_key: PublicKey { ek, vk } }
}
