# Hardened non-TEE mode PoC

> **Status:** PoC / exploratory. Not enabled by default; no migration tooling
> yet. All existing behaviour is unchanged unless `[hardened]
> derive_keys_from_seed = true` is set in `config.toml`.

---

## Problem Statement

A standard `vta-service` (non-TEE) deployment has two high-value secrets
sitting unprotected on the filesystem:

| Secret | Location | Risk |
|---|---|---|
| **JWT signing key** | `config.toml` `[auth] jwt_signing_key` | A `root` user (or anyone with file read) can forge any access token, including super-admin |
| **fjall keyspaces** | `store.data_dir/` (plaintext JSON) | Sessions, ACL entries, audit log, contexts, etc. readable with direct disk access |

TEE mode (`vta-enclave`, Nitro Enclave) closes both gaps via KMS-backed secret
management, but that requires AWS infrastructure and a Nitro-capable instance.

This PoC closes the same two gaps for a self-hosted `vta-service` by tying both
secrets to the master seed — which already lives in a proper secret store
(OS keyring, AWS Secrets Manager, GCP Secret Manager, etc.).

For the **fjall storage encryption** there is one approach: derive the encryption
key from the seed via HKDF. For the **JWT signing key** there are two design
options, described in detail below.

---

## Storage Encryption (same in both JWT options)

The storage-encryption key is derived from the master seed:

```
storage_key = HKDF-SHA256(seed, salt="<config.hardened.storage_key_salt>",
                          info=b"vta-storage-key/v1")
```

This key is passed as `storage_encryption_key: Some(_)` to `server::run()`,
which activates the same `VAE1` AES-256-GCM per-value encryption used in TEE
mode. The salt is stored in `config.toml` as `[hardened] storage_key_salt`
(not secret; treat as a permanent per-instance constant — changing it
invalidates all encrypted data).

---

## JWT Signing Key — Two Options

### Option 1: Derived from seed (deterministic)

The JWT signing key is derived from the master seed using HKDF, with a distinct
info string:

```
jwt_key = HKDF-SHA256(seed, info=b"vta-jwt-signing-key/v1")
```

The derived key bytes are base64url-no-pad encoded and injected into
`config.auth.jwt_signing_key` **in memory only** at boot. Nothing is written
to `config.toml` or to any fjall keyspace.

**Advantages:**
- Simplest to implement — one HKDF call, no additional storage.
- No bootstrap-keyspace state to manage, lose, or tamper with.
- JWT key survives across restarts deterministically (same seed → same key,
  no forced re-login after restart).

**Disadvantages:**
- **JWT key rotation requires seed rotation.** Rotating the master seed is a
  coarse operation — it also rotates every BIP-32 derived key, the storage
  encryption key (requiring re-encryption of all fjall data), and the
  imported-secret KEK. There is no way to change the JWT key independently.
- No tamper-detection fingerprint — any change to the derivation or seed
  silently produces a different key (will manifest as 401s, not a boot error).
- The key space is not independent of the seed: knowing the seed gives an
  attacker both the storage key and the JWT signing key simultaneously.

---

### Option 2: Random key, AES-GCM sealed in bootstrap keyspace (TEE-like)

Mirrors TEE mode exactly, replacing KMS as the KEK with the HKDF-derived
storage key:

- **First boot**: generate a cryptographically random 32-byte JWT key →
  AES-256-GCM encrypt it under the storage key → write
  `hardened:jwt_ciphertext` and `hardened:jwt_fingerprint` to the `bootstrap`
  keyspace (stored unencrypted at the keyspace level, application-layer
  encrypted — same pattern as TEE's `bootstrap:jwt_ciphertext`).
- **Subsequent boots**: read `hardened:jwt_ciphertext` → decrypt with storage
  key → verify SHA-256 fingerprint against `hardened:jwt_fingerprint` → fatal
  exit on mismatch.
- The key is injected into `config.auth.jwt_signing_key` in memory, never
  written to `config.toml`.

**Advantages:**
- **Independent JWT key rotation**: delete `hardened:jwt_ciphertext` and
  `hardened:jwt_fingerprint` from the bootstrap keyspace and restart — a new
  random key is generated. The master seed and all BIP-32 keys are unaffected.
  All existing sessions are invalidated (expected for a key rotation).
- **Tamper detection**: SHA-256 fingerprint check on every boot, same as TEE.
  A mismatch fails the boot with a clear error rather than silently serving
  tokens under a wrong key.
- **Cryptographic independence**: the JWT key is random, not derivable from the
  seed. Compromising the seed does not automatically yield the JWT signing key
  (the attacker would also need to read the encrypted ciphertext from the
  bootstrap keyspace and know the storage key to decrypt it).

**Disadvantages:**
- More moving parts: the `bootstrap` keyspace must persist correctly across
  restarts; a corrupted or deleted `hardened:jwt_ciphertext` row is a boot
  failure (the correct response, but an operational event).
- Slightly more complex boot path vs Option 1.
- The JWT key is stored (encrypted) on disk. In contrast, Option 1's key
  never touches disk at all.

---

## What Was Changed

Four files were touched. No existing behaviour changes unless
`derive_keys_from_seed = true` is set.

### 1. `vta-service/src/hardened.rs` *(new file)*

Storage-key derivation and JWT-key helpers (both options share the storage key
derivation; JWT helpers differ per option):

```rust
// Storage key — same for both JWT options
const STORAGE_KEY_INFO: &[u8] = b"vta-storage-key/v1";

pub fn derive_storage_key(seed: &[u8], salt: &str) -> Zeroizing<[u8; 32]> {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt.as_bytes()), seed)
        .expand(STORAGE_KEY_INFO, &mut key)...;
    Zeroizing::new(key)
}

// Option 1 only
const JWT_KEY_INFO: &[u8] = b"vta-jwt-signing-key/v1";
pub fn derive_jwt_signing_key(seed: &[u8]) -> Zeroizing<[u8; 32]> { ... }

// Option 2 only
pub const HARDENED_JWT_CT_KEY: &str = "hardened:jwt_ciphertext";
pub const HARDENED_JWT_FINGERPRINT_KEY: &str = "hardened:jwt_fingerprint";
pub fn aes_gcm_seal(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> { ... }
pub fn aes_gcm_open(key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> { ... }
pub fn jwt_key_fingerprint(key: &[u8; 32]) -> String { ... } // SHA-256[..16]
```

### 2. `vta-service/src/config.rs`

New `HardenedConfig` struct, added as `pub hardened: HardenedConfig` to
`AppConfig`. Default is disabled, so `config.toml` files without the section
are unaffected.

```toml
[hardened]
derive_keys_from_seed = true
storage_key_salt = "my-unique-per-vta-salt"
```

Fields:

| Field | Default | Description |
|---|---|---|
| `derive_keys_from_seed` | `false` | Enable the PoC. When `true`, both keys are controlled by this module and `[auth] jwt_signing_key` in `config.toml` is ignored |
| `storage_key_salt` | `"vta-storage-v1"` | HKDF salt for the storage key. **Treat as a permanent constant** — changing it invalidates all encrypted data |

### 3. `vta-service/src/main.rs`

In the `None =>` arm (normal `vta` daemon start), after the seed store is
opened, a new block handles hardened mode:

**Option 1 path** (derived JWT key):
```rust
let storage_key = hardened::derive_storage_key(&seed, &salt);
let jwt_key     = hardened::derive_jwt_signing_key(&seed);
drop(seed);
config.auth.jwt_signing_key = Some(BASE64.encode(*jwt_key));
Some(*storage_key)
```

**Option 2 path** (random sealed JWT key):
```rust
let storage_key = hardened::derive_storage_key(&seed, &salt);
drop(seed);
// open bootstrap keyspace (unencrypted, application-layer encrypted)
let bootstrap_ks = store.keyspace(BOOTSTRAP)?;
let jwt_key = match bootstrap_ks.get_raw(HARDENED_JWT_CT_KEY).await? {
    Some(ct) => {
        let key = hardened::aes_gcm_open(&storage_key, &ct)?; // fatal on auth failure
        // verify fingerprint — fatal on mismatch
        key
    }
    None => {
        // first boot: generate random, seal, store + fingerprint
        rand::fill(&mut key_bytes);
        bootstrap_ks.insert_raw(HARDENED_JWT_CT_KEY, hardened::aes_gcm_seal(...));
        bootstrap_ks.insert_raw(HARDENED_JWT_FINGERPRINT_KEY, fingerprint_bytes);
        store.persist().await?;
        key_bytes
    }
};
config.auth.jwt_signing_key = Some(BASE64.encode(jwt_key));
Some(*storage_key)
```

### 4. Setup wizard integration (`from_toml.rs`, `interactive.rs`)

Hardened mode is wired into the `vta setup --from <file>` non-interactive setup
path so operators do not need to hand-edit `config.toml` after setup:

- **`WizardInputs`** (the setup TOML schema) gained a `[hardened]` field of
  type `HardenedConfig`. `WizardInputs` carries `#[serde(deny_unknown_fields)]`
  so the field had to be explicitly added.
- **`apply_inputs`** now checks `inputs.hardened.derive_keys_from_seed`:
  - If `true`: skips the `rand::fill` JWT key generation step entirely
    (produces `jwt_signing_key: None`).
  - If `false` (default): generates a random JWT key as before.
- The saved `AppConfig` uses `hardened: inputs.hardened.clone()` instead of
  `Default::default()`, so the `[hardened]` section in the setup TOML flows
  verbatim into the generated `config.toml`.
- **`interactive.rs`** (the interactive wizard): always emits
  `hardened: Default::default()` — hardened mode is an enterprise feature
  configured only via `--from <toml>`.

#### Setup encryption ordering

For hardened mode, the storage key must be derived before the fjall store is
opened — deriving it requires the seed, and having the key at store-open time
means all keyspace handles are wrapped with `with_encryption(key)` immediately,
so every write is VAE1 from the first byte.

This requires the mnemonic to be generated and the seed to be stored in the
backend **before** `Store::open()` is called. `apply_inputs` step 3.5 in
`from_toml.rs` does this: it generates the mnemonic, confirms with the UI,
stores the seed in the configured backend, derives the storage key, and only
then opens the store and wraps all keyspace handles.

### 5. `vta-service/src/import_did.rs` — offline CLI encryption

Offline CLI commands that write to the fjall store open it **without** the
hardened storage key — they would write plaintext rows that the daemon's
encrypted handles cannot read. Fixed for `import-did`:

```rust
// import_did.rs
let acl_ks = {
    let ks = store.keyspace(ACL)?;
    if config.hardened.derive_keys_from_seed {
        let seed = seed_store.get().await?...;
        let key = *hardened::derive_storage_key(&seed, &salt);
        ks.with_encryption(key)   // same key as daemon
    } else {
        ks
    }
};
```

The same gap exists in other offline CLI commands (`acl_cli`, `keys_cli`,
`webvh_cli`, `bootstrap_cli`, `services_cli`) — see Known Gaps.

### 6. Minor struct-literal patches

`hardened: Default::default()` added to `AppConfig` struct literals in:
- `vta-service/src/setup/from_toml.rs` (two sites)
- `vta-service/src/test_support.rs`

---

## The `storage_key_salt` — TEE vs Hardened

Both TEE and hardened use exactly the same pattern: the salt is a field in
`config.toml` with a hardcoded serde default if the operator omits it.

| | TEE | Hardened |
|---|---|---|
| Config field | `[tee] storage_key_salt` | `[hardened] storage_key_salt` |
| Default value | `"vta-tee-storage-v1"` | `"vta-storage-v1"` |
| Set by | Operator in `config.toml` / baked into EIF | Operator in setup TOML → flows into `config.toml` |
| Auto-generated? | **No** | **No** |

**Implication:** every VTA that accepts the default uses the same salt. If two
VTAs ever share the same master seed (e.g. a restore to a different instance),
they derive the same storage encryption key. The salt is a domain-separator,
not a secret — its confidentiality doesn't matter — but it should be unique
per VTA instance for key-independence. Set it explicitly in the setup TOML;
do not change it after first boot (it invalidates all encrypted data).

The TEE architecture doc (`docs/02-vta/tee-architecture.md`) shows the same
field in `[tee.kms]` and gives the same advice for TEE deployments.

---

## TEE vs Option 1 vs Option 2: Side-by-Side Comparison

### Storage encryption (fjall keyspaces)

All three modes converge on the same `apply_encryption` closure in
`server::build_app_state()` — the `VAE1` AES-256-GCM result is identical.
The difference is only how the key arrives there.

| | TEE (`vta-enclave`) | [hardened] derive_keys_from_seed = true |
|---|---|---|
| **Storage key origin** | `HKDF(seed, salt, info="aes-256-gcm-storage")` after KMS `Decrypt` inside enclave | `HKDF(seed, salt, info="vta-storage-key/v1")` after `seed_store.get()` |
| **Seed protection** | KMS + PCR-bound attestation | External secret store (keyring, AWS SM, …) |
| **Salt location** | `config.tee.storage_key_salt` | `config.hardened.storage_key_salt` |
| **Trust anchor** | Only the exact measured enclave image can decrypt the seed | IAM / OS keyring access controls on the secret store |
| **VAE1 encryption** | ✓ | ✓ |

### JWT signing key

| | TEE (`vta-enclave`) | Option 1: Derived | Option 2: Sealed |
|---|---|---|---|
| **Origin** | Random — `rand::fill` on first boot inside enclave | Deterministic — `HKDF(seed, info="vta-jwt-signing-key/v1")` | Random — `rand::fill` on first boot |
| **At-rest storage** | `bootstrap:jwt_ciphertext` (AES-GCM under KMS data key) + `bootstrap:jwt_fingerprint` | **Nothing** — re-derived from seed on every boot | `bootstrap:hardened:jwt_ciphertext` (AES-GCM under storage key) + `bootstrap:hardened:jwt_fingerprint` |
| **KEK for ciphertext** | KMS-generated data key (PCR-bound) | N/A — never stored | HKDF-derived storage key |
| **Fingerprint / tamper detection** | ✓ SHA-256 fingerprint checked every boot; mismatch → fatal | ✗ None — silent wrong key if seed/derivation changes | ✓ SHA-256 fingerprint checked every boot; mismatch → fatal |
| **Survival across restarts** | ✓ Same key (KMS decrypt) | ✓ Same key (re-derived) | ✓ Same key (AES-GCM decrypt) |
| **Independent JWT rotation** | ✓ Delete `bootstrap:jwt_ciphertext` + restart | ✗ Requires full seed rotation | ✓ Delete `bootstrap:hardened:jwt_ciphertext` + restart |
| **Disk exposure** | Only KMS-wrapped ciphertext on disk | Key never on disk (but re-derivable from the seed) | AES-GCM ciphertext on disk (decryptable only with storage key) |
| **`config.toml`** | Field absent — generated in enclave | Field absent — injected in memory | Field absent — injected in memory |
| **Complexity** | High (KMS, vsock, PCR policy) | Low — one HKDF call | Medium — first-boot vs subsequent-boot logic, fingerprint check |

---

## How to Enable — Fresh VTA

### Preferred: via `vta setup --from <toml>` (no manual config editing)

Create a setup TOML with a `[hardened]` section:

```toml
# setup-hardened.toml
config_path = "/etc/vta/config.toml"
data_dir    = "/var/lib/vta/data"

[secrets]
# Choose a real backend — OS keyring default, or cloud:
# aws_secret_name = "my-vta/master-seed"
# aws_region = "eu-west-1"

[hardened]
derive_keys_from_seed = true
storage_key_salt = "choose-a-unique-string-per-vta"   # permanent — never change

[vta_did]
# e.g. { type = "create_webvh", url = "https://vta.example.com" }
```

Run setup:
```bash
vta setup --from setup-hardened.toml
```

**What the wizard does with `derive_keys_from_seed = true`:**
- Skips generating `jwt_signing_key` (no `rand::fill`, no base64 encode).
- Writes `jwt_signing_key` as **absent** from `[auth]` in `config.toml`.
- Writes the `[hardened]` section verbatim to `config.toml`.

**Generated `config.toml` will contain:**
```toml
[auth]
# jwt_signing_key is absent — derived from seed at every boot

[hardened]
derive_keys_from_seed = true
storage_key_salt = "choose-a-unique-string-per-vta"
```

### Alternative: manual edit after standard setup

1. Run `vta setup` as normal (creates `config.toml` with a random `jwt_signing_key`).
2. Remove `jwt_signing_key` from `[auth]` in `config.toml`.
3. Add the `[hardened]` section:
   ```toml
   [hardened]
   derive_keys_from_seed = true
   storage_key_salt = "choose-a-unique-string-per-vta"
   ```

### On first daemon boot

Start the daemon. Expected log output:
- **Storage key**: `INFO hardened mode: storage-encryption key derived from seed, JWT signing key loaded from bootstrap keyspace (neither stored on disk)`
- **JWT key (first boot)**: `INFO hardened mode: new random JWT signing key generated and sealed in bootstrap keyspace`
- **JWT key (subsequent boots)**: `INFO hardened mode: JWT signing key decrypted from bootstrap keyspace`

> If you see `WARN SECURITY: VTA_AUTH_JWT_SIGNING_KEY was set in the environment`,
> the env var was set in your deployment config. The daemon removes it from the
> process environment automatically, but remove it from your deployment manifest
> to stop the warning.

### Rotating the JWT key

- **Option 1**: no independent rotation — must rotate the master seed (`vta keys rotate-seed`). This also changes the storage encryption key, requiring a re-encryption pass of all fjall data.
- **Option 2**: delete `hardened:jwt_ciphertext` and `hardened:jwt_fingerprint` from the `bootstrap` keyspace (no CLI command yet — see Known Gaps) and restart. The master seed and all fjall data are unaffected. All existing sessions are invalidated.

---

## Migration for Existing (Plaintext-Fjall) VTAs

Enabling `derive_keys_from_seed = true` on a VTA that was originally set up
**without** hardened mode will cause read failures — the `VAE1` decoder cannot
decrypt plaintext rows.

A `KeyspaceHandle::migrate_to_encrypted(key)` API exists in
`vti-common/src/store/mod.rs` that re-writes rows in place. A CLI command
(`vta migrate-to-encrypted`) to drive it is **not yet implemented**.

Workaround: only enable hardened mode on freshly-setup VTAs.

---

## Known Gaps and Future Work

| Gap | Applies to | Description | Status | Estimate |
|---|---|---|---|---|
| `vta migrate-to-encrypted` CLI | Both options | Required to safely enable hardened mode on a VTA originally set up without it | Open | ~3 d |
| `vta hardened rotate-jwt` CLI | Option 2 | Convenience command to delete `hardened:jwt_ciphertext` + `hardened:jwt_fingerprint` and trigger a restart | Open | ~0,5 d |
| Remaining offline CLI commands | Both options | `acl_cli`, `keys_cli`, `webvh_cli`, `bootstrap_cli`, `services_cli` write to the store without the hardened storage key — same issue fixed for `import_did`. Each command needs the same seed-load + `with_encryption` pattern | Open | ~2 d |
| Setup encryption ordering | Both options | Seed generated before store opens; all writes VAE1 from first byte; implemented in `apply_inputs` step 3.5 | Fixed (PoC) | — |
| `VTA_AUTH_JWT_SIGNING_KEY` env var exposure | Both options | Removed from process env at boot; see section below | Fixed (PoC) | — |
| `BackupPayload` non-`Zeroizing` strings in memory | Both options | Seed + JWT key + imported privkeys assembled as plain `String` before Argon2id encryption; see section below | Open | ~0,5 d |

---

## `VTA_AUTH_JWT_SIGNING_KEY` environment variable exposure

### Problem

In non-KMS mode, `AppConfig::load()` calls `apply_env_overrides()` which reads
`VTA_AUTH_JWT_SIGNING_KEY` and writes the value into `config.auth.jwt_signing_key`
before the hardened boot block runs. The hardened block then overwrites it with the
derived/sealed key, so the env var has no effect on what key is actually used.

However, the value remains **visible in `/proc/<pid>/environ`** to any `root` reader,
in `docker inspect`, in `kubectl describe pod`, in CI logs if `env` is echoed, and
in cloud provider instance metadata collectors. An operator who previously stored the
JWT key in the env var and then switched to hardened mode may not have removed it.

### Mitigation applied (PoC)

When `hardened.derive_keys_from_seed = true` and `VTA_AUTH_JWT_SIGNING_KEY` is found
in the process environment, the hardened boot block in `vta-service/src/main.rs`:

1. Emits a `warn!` telling the operator to remove it from their deployment config.
2. Calls `std::env::remove_var("VTA_AUTH_JWT_SIGNING_KEY")` — this **actively removes
   the value from the process environment block**, so it is no longer visible in
   `/proc/<pid>/environ` after that point in startup.

The `remove_var` call is `unsafe` in Rust (race with other threads reading the env),
annotated with a `// SAFETY:` comment — it is safe here because no other thread has
started yet at this point in `main()`.

### What is NOT done

`VTA_AUTH_JWT_SIGNING_KEY` is still read by `apply_env_overrides` (called inside
`AppConfig::load`) **before** the hardened block runs, so its value briefly lives in
`config.auth.jwt_signing_key` for the microseconds between config load and the
hardened block overwriting it. This transient in-memory exposure is acceptable — it
never reaches disk or logs (the field is `Debug`-redacted), and the hardened block
immediately replaces it with the derived/sealed key.

---

## `BackupPayload` in-memory non-`Zeroizing` strings

### Problem

The backup export assembles all key material into a `BackupPayload` struct before
encrypting it with Argon2id + AES-256-GCM. Several fields are heap-allocated
`String` values that are **not `Zeroizing`**:

```rust
// vta-service/src/operations/backup/mod.rs
let active_seed_hex = hex::encode(&seed_bytes);      // String, not Zeroizing
let payload = BackupPayload {
    active_seed_hex,       // full BIP-39 master seed as hex String
    jwt_signing_key,       // JWT signing key as base64 String
    imported_secrets: vec![ImportedSecretBackup {
        private_key_hex: hex::encode(&plaintext),    // imported privkeys as hex String
    }],
    ...
};
```

These strings linger on the heap until the allocator reuses the memory. A core dump,
crash report, memory forensics tool, or a language-level heap scan taken during a
backup export window will find plaintext key material.

The on-disk `.vtabak` output is protected (Argon2id + AES-256-GCM), so there is
no plaintext-at-rest exposure from the backup operation itself. This is an
**in-memory-only** window.

### Relationship to the hardened PoC

The hardened PoC does not touch `backup/mod.rs` at all. The gap exists in both
hardened and standard deployments, and equally in TEE mode (where the same
`BackupPayload` struct is used for the backup-import restore path).

### Fix (not yet implemented)

Change `BackupPayload` field types:

```rust
// Before
active_seed_hex: String,
jwt_signing_key: Option<String>,

// After
active_seed_hex: zeroize::Zeroizing<String>,
jwt_signing_key: Option<zeroize::Zeroizing<String>>,
```

Add `#[derive(zeroize::ZeroizeOnDrop)]` to `BackupPayload` and
`ImportedSecretBackup`. This ensures all key material is overwritten when the
struct drops, closing the post-encryption window.

The `zeroize` crate is already a workspace dependency. The
change is purely additive — `Zeroizing<String>` derefs to `String` so all
existing call sites compile unchanged.
