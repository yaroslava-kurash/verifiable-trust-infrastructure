//! Non-TEE hardened mode: derive the storage-encryption key from the master
//! seed, and manage the JWT signing key as an AES-GCM ciphertext stored in
//! the `bootstrap` keyspace — mirroring how TEE mode handles both.
//!
//! # Purpose
//!
//! Standard `vta-service` (non-TEE) boots with:
//!   - The JWT signing key stored in plaintext in `config.toml` — the
//!     highest-value secret on the filesystem; a root user can forge any token.
//!   - The fjall keyspaces unencrypted at rest — sessions, ACL entries, audit
//!     logs, etc. readable by anyone with disk access.
//!
//! This module closes both gaps **without a Nitro enclave or KMS**:
//!
//! 1. At boot, load the master seed from the configured secret-store backend.
//! 2. Derive the **storage-encryption key** via `HKDF-SHA256(seed, salt, info
//!    = "vta-storage-key/v1")` and pass it to `server::run()` as
//!    `storage_encryption_key: Some(_)` — the `VAE1` AES-256-GCM
//!    per-value encryption layer activates.
//! 3. **JWT signing key** — mirrors TEE exactly, replacing KMS with the
//!    HKDF-derived storage key as the KEK:
//!    - **First boot**: generate a random 32-byte JWT key, AES-GCM encrypt it
//!      under the storage key, write `hardened:jwt_ciphertext` +
//!      `hardened:jwt_fingerprint` to the `bootstrap` keyspace (stored
//!      unencrypted at the keyspace level, application-layer encrypted).
//!    - **Subsequent boots**: read the ciphertext, decrypt with the storage
//!      key, verify the SHA-256 fingerprint.
//!    - The JWT key is **never written to `config.toml`**.
//!    - **Independent rotation**: delete `hardened:jwt_ciphertext` and
//!      `hardened:jwt_fingerprint` from the `bootstrap` keyspace, then
//!      restart — a new random key is generated. This does **not** require
//!      rotating the master seed (unlike the previous derived-key approach).
//!
//! Both features require the seed to be in a **real** secret-store backend
//! (OS keyring, AWS/GCP/Azure/Vault/K8s). The plaintext file fallback
//! defeats the protection and triggers a startup warning.
//!
//! # Migration from derived-key approach
//!
//! If you previously ran with the now-removed `derive_jwt_signing_key`
//! function, the VTA will generate a new random JWT key on next boot and
//! store it in `bootstrap:hardened:jwt_ciphertext`. All existing sessions
//! will be invalidated (access tokens signed under the old key will be
//! rejected). This is expected behaviour for a JWT key rotation.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use sha2::Sha256 as Sha256Hasher;
use zeroize::Zeroizing;

/// fjall key for the AES-GCM ciphertext of the JWT signing key.
/// Stored in the `bootstrap` keyspace (unencrypted at rest — application-layer
/// encrypted under the storage key, matching TEE's `bootstrap:jwt_ciphertext`).
pub const HARDENED_JWT_CT_KEY: &str = "hardened:jwt_ciphertext";

/// fjall key for the SHA-256 fingerprint of the JWT signing key.
/// Tamper-detection: mismatch on boot → fatal, same as TEE's fingerprint check.
pub const HARDENED_JWT_FINGERPRINT_KEY: &str = "hardened:jwt_fingerprint";

/// HKDF `info` for the storage-encryption key.
///
/// Domain-separated from the VTC counterpart (`vtc-storage-key/v1`) so the
/// same seed never yields the same material for two different services.
const STORAGE_KEY_INFO: &[u8] = b"vta-storage-key/v1";

/// Derive the 32-byte AES-256-GCM storage-encryption key from `seed`.
///
/// `salt` must match `config.hardened.storage_key_salt`. **Changing the salt
/// invalidates all encrypted data** — treat it as a permanent per-VTA constant
/// set once at initial setup.
///
/// Deterministic: same seed + same salt → same key on every boot.
pub fn derive_storage_key(seed: &[u8], salt: &str) -> Zeroizing<[u8; 32]> {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt.as_bytes()), seed)
        .expand(STORAGE_KEY_INFO, &mut key)
        .expect("32-byte output is within HKDF-SHA256 limits");
    Zeroizing::new(key)
}

/// AES-256-GCM encrypt `plaintext` under `key`.
/// Returns `[12-byte nonce || ciphertext+tag]` — same wire format as the
/// TEE `aes_gcm_encrypt` helper in `kms_bootstrap.rs`.
pub fn aes_gcm_seal(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    use aes_gcm::aead::rand_core::RngCore;
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let mut nonce_bytes = [0u8; 12];
    aes_gcm::aead::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let mut ct = cipher.encrypt(nonce, plaintext).expect("AES-GCM encrypt");
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.append(&mut ct);
    out
}

/// AES-256-GCM decrypt a `[12-byte nonce || ciphertext+tag]` blob.
/// Returns `None` on authentication failure (tampered or wrong key).
pub fn aes_gcm_open(key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 13 {
        return None;
    }
    let nonce = aes_gcm::Nonce::from_slice(&blob[..12]);
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    cipher.decrypt(nonce, &blob[12..]).ok()
}

/// Compute a SHA-256 fingerprint of a JWT signing key for tamper detection.
/// Returns the first 16 bytes as 32 hex characters — same as TEE's `jwt_fingerprint`.
pub fn jwt_key_fingerprint(key: &[u8; 32]) -> String {
    let hash = Sha256Hasher::digest(key);
    hex::encode(&hash[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Derivation is deterministic: same inputs → same output.
    #[test]
    fn derive_storage_key_is_deterministic() {
        let seed = [0x42u8; 32];
        let k1 = derive_storage_key(&seed, "test-salt");
        let k2 = derive_storage_key(&seed, "test-salt");
        assert_eq!(*k1, *k2);
    }

    /// Different salts produce different storage keys (domain separation).
    #[test]
    fn derive_storage_key_differs_by_salt() {
        let seed = [0x42u8; 32];
        let k1 = derive_storage_key(&seed, "salt-a");
        let k2 = derive_storage_key(&seed, "salt-b");
        assert_ne!(*k1, *k2);
    }

    /// AES-GCM seal/open round-trips correctly.
    #[test]
    fn aes_gcm_seal_open_roundtrip() {
        let key = [0xABu8; 32];
        let plaintext = b"a 32-byte jwt signing key value!";
        let ct = aes_gcm_seal(&key, plaintext);
        let pt = aes_gcm_open(&key, &ct).expect("open should succeed");
        assert_eq!(pt, plaintext);
    }

    /// AES-GCM open fails with a different key (authentication failure).
    #[test]
    fn aes_gcm_open_fails_with_wrong_key() {
        let key = [0xABu8; 32];
        let wrong_key = [0xCDu8; 32];
        let ct = aes_gcm_seal(&key, b"secret jwt key bytes go here!!!");
        assert!(aes_gcm_open(&wrong_key, &ct).is_none());
    }

    /// AES-GCM open fails on a tampered ciphertext.
    #[test]
    fn aes_gcm_open_fails_on_tampered_ciphertext() {
        let key = [0x11u8; 32];
        let mut ct = aes_gcm_seal(&key, b"secret jwt key bytes go here!!!");
        let mid = ct.len() / 2;
        ct[mid] ^= 0xFF;
        assert!(aes_gcm_open(&key, &ct).is_none());
    }

    /// JWT fingerprint is deterministic and 32 hex chars.
    #[test]
    fn jwt_key_fingerprint_is_deterministic() {
        let key = [0xABu8; 32];
        let fp1 = jwt_key_fingerprint(&key);
        let fp2 = jwt_key_fingerprint(&key);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 32);
    }

    /// Different keys produce different fingerprints.
    #[test]
    fn jwt_key_fingerprint_differs_by_key() {
        let fp1 = jwt_key_fingerprint(&[0x01u8; 32]);
        let fp2 = jwt_key_fingerprint(&[0x02u8; 32]);
        assert_ne!(fp1, fp2);
    }
}

