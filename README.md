# pqc-signcrypt

A cute lil experiment at building a signcryption scheme out of post-quantum cryptography algorithms
(i.e. ML-KEM-786, ML-DSA-65, a KDF, and an AEAD or your fave IND-CPA stream cipher and a PRF-secure
MAC).

## CAUTION

⚠️ You should not use this. ⚠️

Neither the design nor the implementation of this library have been independently evaluated. The
design is documented here; read it and see if the arguments therein are convincing.

## The Security Model

This scheme aims to be both confidential and unforgeable in the multi-user insider model for
asymmetric cryptography, in which the adversary is given all private keys except for one and full
access to a decryption oracle.

For a scheme to be confidential (i.e. IND-CCA2), the adversary is given all decryption keys except
for one and then must distinguish between two encrypted messages (without access to the decryption)
oracle.

For a scheme to be unforgeable (i.e. sUF-CMA), the adversary is given all signing keys except for
one and then must create or modify a ciphertext such that it remains valid.

## Generic Signcryption Composition Schemes

Before we get into this scheme, we should go over the various generic composition schemes which
attempt to provide signcryption using generic encryption and signature algorithms and why they don't
have what we're looking for.

### Encrypt-and-Sign (E&S)

Encrypt-and-Sign encrypts the plaintext, signs the plaintext, and concatenates the ciphertext and
signature:

```rust
fn encrypt_and_sign(ek: &EncryptingKey, sk: &SigningKey, m: &[u8]) -> Vec<u8> {
    let c = encrypt(ek, m);
    let s = sign(sk, m);
    [c, s].concat()
}
```

This has the virtue of being able to perform both asymmetric operations in parallel, but nothing
about the definition of an sUF-CMA digital signature algorithm requires confidentiality. In the
two-user IND-CCA2 game, an adversary need only check the signature of a ciphertext to distinguish
between two plaintexts.

### Encrypt-then-Sign (EtS)

Encrypt-then-Sign encrypts the plaintext, signs the ciphertext, and concatenates the ciphertext and
signature.

```rust
fn encrypt_then_sign(ek: &EncryptingKey, sk: &SigningKey, m: &[u8]) -> Vec<u8> {
    let c = encrypt(ek, m);
    let s = sign(sk, c);
    [c, s].concat()
}
```

Unlike E&S, this has the virtue of not requiring confidentiality from the signature algorithm or
being vulnerable to trivial distinguishing attacks, but it's still not IND-CCA2 secure. An adversary
in the two-user insider model in possession of the sender's signing key can strip the signature,
modify the ciphertext, re-sign it, and use the decryption oracle to decrypt the modified ciphertext
without having the receiver's decryption key.

In the multi-user outsider model, this scheme's confidentiality is trivially broken, as the
ciphertexts are not bound to the identities of the sender and receiver, allowing an adversary in
possession of public keys only to strip the signature, re-sign it with an arbitrary signing key, and
submit it to the decryption oracle.

### Sign-then-Encrypt (StE)

Sign-and-Encrypt signs the plaintext, concatenates the plaintext and signature, and encrypts the
two to produce the ciphertext.

```rust
fn sign_then_encrypt(ek: &EncryptingKey, sk: &SigningKey, m: &[u8]) -> Vec<u8> {
    let s = sign(sk, m);
    encrypt(ek, [m, s].concat())
}
```

The signature is encrypted, so this is also not vulnerable to trivial distinguishing attacks nor can
the signature be stripped to produce a modified ciphertext. But it's not sUF-CMA secure, because an
adversary in the two-user insider model with the receiver's decryption key can decrypt the
ciphertext and re-encrypt it with the receiver's encryption key to produce a forged ciphertext.

In the multi-user outsider model, this scheme's authenticity is also trivially broken. An adversary
in possession of public keys only can use a signcryption oracle to create a valid ciphertext for an
arbitrary receiver under its control, decrypt the plaintext and signature, and re-encrypt it with
the receiver's encrypting key to produce a forged ciphertext.

## Lessons Learned

Given the inability of the generic compositions to achieve IND-CCA2/sUF-CMA in the multi-user
insider model, we can draw some conclusions about what a scheme which does would look like:

1. All outputs must be bound to the identities of the parties, thus preventing unknown key share
   attacks in the multi-user model.
2. All outputs must be encrypted with the receiver's decryption key. E&S allows for trivial
   distinguishing attacks and potentially message recovery because the signature is in plaintext.
3. The value which is signed must commit to both the plaintext and the receiver's decryption key.
   EtS allows for signature stripping because the value being signed is a public value (i.e. the
   ciphertext), allowing an adversary in possession of the sender's signing key to sign a modified
   ciphertext.

## The Scheme

In generic terms, the scheme uses an IND-CCA2-secure KEM (`encapsulate`/`decapsulate`), a
UF-CMA-secure signature algorithm (`sign`/`verify`), an IND-CPA-secure symmetric encryption
algorithm (`encrypt`/`decrypt`), a KDF-secure key derivation algorithm (`kdf`), and PRF-secure MAC
(`mac`).

```rust
fn signcrypt(sender: &PrivateKey, receiver: &PublicKey, m: &[u8]) -> Vec<u8> {
    // Encapsulate a key using the receiver's encryption key.
    let (c0, k0) = encapsulate(receiver.ek);

    // Derive two symmetric keys from the parties' identities, the encapsulated key, and the shared secret.
    let k1 = kdf(sender.public_key, receiver, c0, k0, "confidentiality");
    let k2 = kdf(sender.public_key, receiver, c0, k0, "authenticity");

    // Encrypt the plaintext using the first symmetric key.
    let c1 = encrypt(k1, m);

    // Create a MAC of the ciphertext using the second symmetric key.
    let h0 = mac(k2, c1);

    // Sign the MAC.
    let sig = sign(sender.sk, h0);

    // Encrypt the signature.
    let c2 = encrypt(k1, sig);

    // Return the KEM ciphertext, the encrypted message, and the encrypted signature.
    [c0, c1, c2].concat()
}
```

### IND-CCA2 Security

To evaluate the IND-CCA2 security of the scheme in the multi-user insider model, we establish a key
pair for a receiver and a sender. We give an adversary access to the key generation procedure, the
signcryption procedure, the unsigncryption procedure, all public keys, the sender's private key,
plus access to an unsigncryption oracle which allows them to unsigncrypt ciphertexts using the
receiver's private key. The adversary is allowed to make an arbitrary use of these. Finally, we
choose a random bit and signcrypt it with the sender's private key and the receiver's public key.
The adversary is given the ciphertext and access again to all the previous capabilities. If they can
determine the value of the bit with a probability greater than 50% without using the unsigncryption
oracle to unsigncrypt it, they win and the scheme is not IND-CCA2-secure.

The adversary in this game can trivially encapsulate new keys, but is unable to decapsulate the key
from the challenge ciphertext as they don't have the receiver's private key. They therefore cannot
recover either the plaintext bit or the plaintext signature unless either the KEM is not
IND-CCA2-secure or the symmetric encryption is not IND-CPA secure.

If the adversary modifies the encapsulated key part of the ciphertext and presents it to the oracle,
the decapsulated key will be different which will result in a different MAC key, a different MAC,
and thus the signature invalid unless either the KEM is not IND-CCA2-secure, the MAC is not
PRF-secure, or the signature is not sUF-CMA-secure.

If the adversary modifies the encrypted message part of the ciphertext and presents it to the oracle,
the decapsulated key will be the same but the MAC of the modified ciphertext will be different and
thus the signature invalid unless the MAC is not PRF-secure or the signature is not sUF-CMA-secure.
The adversary can trivially create new signatures with the sender's private key, but cannot forge a
MAC of the modified ciphertext without the decapsulated key.

If the adversary modifies the encrypted signature part of the ciphertext and presents it to the
oracle, the decapsulated key will be the same, the MAC will be the same, but the signature will be
invalid unless the signature is not sUF-CMA secure.

### sUF-CMA Security

To evaluate the sUF-CMA security of the scheme in the multi-user insider model, we establish a key
pair for a receiver and a sender. We give an adversary access to the key generation procedure, the
signcryption procedure, the unsigncryption procedure, all public keys, the receiver's private key,
plus access to a signcryption oracle which allows them to signcrypt plaintexts using the
sender's private key. The adversary is allowed to make an arbitrary use of these. If the adversary
can produce a ciphertext which successfully unsigncrypts with the receiver's private key without
using the signcryption oracle, they win and the scheme is not sUF-CMA-secure.

The adversary in this game can trivially decapsulate keys and thus recover the plaintext values of
any messages and their signatures but is unable to create new signatures as they don't have the
sender's private key unless the signature is not sUF-CMA-secure.

If the adversary creates a new encapsulated key for an existing ciphertext and presents it to the
oracle, the decapsulated key will be different which will result in a different MAC key, a different
MAC, and thus the signature invalid unless either the KEM is not IND-CCA2-secure, the MAC is not
PRF-secure, or the signature is not sUF-CMA-secure.

If the adversary strips the signature from an existing encapsulated key and encrypted message, they
can use the decapsulated key to encrypt a new signature of their choosing. Without access to the
sender's private key, however, they cannot forge a valid signature unless the signature is not
sUF-CMA-secure.

## Implementation

This implementation uses [Lockstitch](https://github.com/codahale/lockstitch), which doesn't do
_exactly_ what I described but is functionally equivalent. It uses ML-KEM-768 for the KEM, ML-DSA-65
for the signature, TurboSHAKE128 for the KDF, and AEGIS-128L for both the encryption and MAC. It's
not as easy to describe but is easier to implement.

## License

Copyright © 2024 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
