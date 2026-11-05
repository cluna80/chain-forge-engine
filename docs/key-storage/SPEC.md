# Encrypted key storage for ML-DSA-65 production keys — threat model and file format (issue #107)

Status: **proposal, written before implementation** (owner direction 2026-11-05: encrypted private-key storage; restrictive
Windows ACLs verified, not assumed; Unix owner-only preserved; fail closed; no plaintext production keys; do not store seed and
expanded key together without need; controlled migration; no weakening of signing v2). Draft PR stacked on #106 (`qcb-keygen`).

## 1. Reuse decision (wallet format)

The wallet (`chain-forge-wallet`) encrypts an ML-DSA key with **Argon2id (128 MiB, t=3, p=4, 32-byte salt) → AES-256-GCM
(12-byte random nonce)**. Those primitives and parameters are appropriate and are **kept**. The wallet *container* is not
reused as is, because:

| Property | Wallet container | Needed |
|---|---|---|
| Format version / algorithm identifiers | none | explicit `version`, KDF and cipher ids, so a change is detectable |
| Associated data | **none**: label, address, public key and KDF parameters are unauthenticated | all header fields authenticated (AEAD AAD) |
| Payload kind | always the expanded secret key | `seed` (preferred) or `expanded-secret-key` (legacy keys that have no seed) |
| KDF parameter bounds | none (a file can ask for any memory/time) | floor (weak files refused) and ceiling (DoS-sized files refused) |
| Strict parsing | lenient | unknown fields, wrong types, bad hex/lengths all refused |
| In-memory handling | plain `Vec<u8>` | zeroized buffers for passphrase, derived key, seed (best effort, see §8) |

The wallet is **not changed** by this work; a future wallet migration to this container is a separate decision.

## 2. Assets, adversaries, scope

Assets: the ML-DSA-65 private key (seed or expanded form), the passphrase, the key file's integrity (a swapped public key or
address must not be accepted), the KDF cost (so a stolen file costs the attacker real work).

In scope (the format and the file-handling code defend against):
* **A1 — offline thief** with a copy of the key file (backup, stolen disk, mis-shared folder): must need the passphrase; Argon2id
  cost per guess at the production parameters; no secret in the clear in the file.
* **A2 — file tamperer** who can edit the file but does not know the passphrase: any change to a header field or to the
  ciphertext must be detected (AEAD). A malicious file must not force unbounded memory/time (KDF ceiling).
* **A3 — local other user** on a shared machine: the file and its directory must not be readable or writable by other accounts
  (Unix mode bits; Windows DACL). Loading **verifies the actual permissions** and refuses a key file whose permissions were loosened.
* **A4 — operator mistakes**: overwriting an existing key, printing a key to a terminal/log, passing the passphrase on the command line.

Out of scope / not defended (see §8): an attacker with the passphrase; malware running as the same user (can read process memory
or keylog); root/Administrator/SYSTEM (can always override file permissions); cold-boot/swap/hibernation leakage; side channels
of hedged signing; a compromised RNG; the scheduler's secret-in-request-body exposure (a separate blocking workstream).

## 3. File format `qattice-key` version 1

UTF-8 JSON object, **all fields required, no unknown fields**, at most 64 KiB:

```json
{
  "format": "qattice-key",
  "version": 1,
  "scheme": "ml-dsa-65",
  "label": "<free text, <= 128 bytes>",
  "address": "<post-quantum address derived from public_key>",
  "public_key": "<1952 bytes, lowercase hex>",
  "payload_kind": "seed" | "expanded-secret-key",
  "kdf":    { "algorithm": "argon2id", "version": 19, "m_cost_kib": 131072, "t_cost": 3, "p_cost": 4, "salt": "<32 bytes hex>" },
  "cipher": { "algorithm": "aes-256-gcm", "nonce": "<12 bytes hex>" },
  "ciphertext": "<hex: payload || 16-byte GCM tag>"
}
```
* `payload_kind = "seed"`: payload is the 32-byte FIPS 204 seed ξ (ciphertext 48 bytes). The expanded key is **not stored**; it is
  regenerated in memory with the conforming key generation. This is the default for every newly generated key.
* `payload_kind = "expanded-secret-key"`: payload is the 4,032-byte secret key (ciphertext 4,048 bytes). Used **only** to migrate
  keys made by the legacy library, which have no FIPS 204 seed.
* Key derivation: `Argon2id(passphrase, salt, m_cost_kib, t_cost, p_cost, 32 bytes, version 0x13)`. Production defaults
  `131072 / 3 / 4`. **Bounds** enforced on create and on load: floor `19456 / 2 / 1`, ceiling `1048576 / 10 / 16`.
* A fresh random salt and nonce per file (so two files never share a key/nonce pair).
* **AAD** (authenticated, not encrypted) = `"qattice-key/v1" || 0x00` followed by, for each of `format, version, scheme, label,
  address, public_key, payload_kind, kdf.algorithm, kdf.version, kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, kdf.salt,
  cipher.algorithm, cipher.nonce`, in that order, `U32_BE(length) || bytes` (numbers as ASCII decimal, binary fields as raw
  bytes). Every header byte is therefore bound to the ciphertext.
* After decryption the loader **recomputes** the public key (from the seed, or by validating the expanded key against the stored
  public key) and the address, and refuses a mismatch. A wrong passphrase and a tampered file are reported identically.

## 4. Operations and fail-closed rules

* `create`: validate passphrase policy (>= 12 bytes) and KDF bounds → obtain randomness (error ⇒ abort) → create the directory
  restricted (or verify it) → create the file with `create_new` (never overwrites) and owner-only permission → **verify** the
  permission → derive, encrypt, write, `fsync` → re-verify. **Any failure removes the file this call created**; no partially written
  or unprotected key file is left behind.
* `load`: verify the file's and its directory's real permissions first → size cap → strict parse → bounds → derive → decrypt →
  recompute and compare public key/address. Any failure returns an error and no key material.
* Passphrases are never accepted on the command line. Sources: `--passphrase-file <path>`, the `QCB_KEY_PASSPHRASE` environment
  variable, or a prompt on stdin. Errors never contain a passphrase, seed or key.

## 5. Permissions

* **Unix**: key file `0600`; directory created `0700`. An existing directory must not be group- or other-writable; otherwise creation
  fails unless the operator passes `--harden-existing-dir` (which sets `0700`). Loading refuses a key file that is not `0600`-class
  (no group/other bits).
* **Windows**: file and (new) directory get a **protected DACL** (inheritance removed) containing **exactly one allow ACE for the
  current user's SID**. The tool then **reads the DACL back** (`icacls <path> /save`, SDDL, locale-independent) and verifies
  protected + a single non-inherited allow ACE for that SID with no other trustee; verification failure ⇒ error and the file is
  removed. Loading repeats the verification. An existing directory is verified and refused unless `--harden-existing-dir`.
  Administrators/SYSTEM can always take ownership; that is a limitation, not a goal.

## 6. Migration from the plaintext `qcb-keygen` format (#106)

`qcb-keygen key-migrate --from <plaintext.json> --out <key file>`:
* never modifies, deletes or prints the source file (its bytes are unchanged; the operator removes it after verifying);
* refuses an existing `--out`; validates the plaintext key (consistency, seed→public key, address) **before** creating anything;
* `mldsa-v2` files that contain a seed become `payload_kind = "seed"` (the stored expanded key is dropped); legacy `mldsa` files
  (no seed) become `payload_kind = "expanded-secret-key"`;
* decrypts the new file and compares it with the source before reporting success.
Genesis hashes and signing behaviour are untouched: this is a key container, not a signing path. Signing v2 (FIPS 204, hedged, full
preimage) is unchanged and there is no legacy fallback.

## 7. Test plan (tests first)

Library + binary tests: round trip; no plaintext secret or secret field in the file; wrong passphrase; **every header field
tampered**; ciphertext bit flips; KDF floor/ceiling on create and load; passphrase policy; RNG failure, permission-enforcement
failure and file-creation failure leave no file; no overwrite; fresh salt/nonce; permissions verified on load (loosened file
refused); migration (source byte-identical, damaged source creates nothing, legacy key becomes expanded kind); CLI never prints
secrets and rejects a passphrase on argv; SDDL verifier unit tests (accept one protected ACE; reject Everyone, two ACEs,
inherited, unprotected, wrong SID). Windows-only tests apply the real ACLs and read them back. Mutation checks on each defence.

## 8. Explicit limitations

* Same-user malware and memory disclosure are not defended; zeroization is best effort (the fips204 `KeyPair` and copies made
  by the standard library are not zeroized; the OS may swap pages).
* Administrators/SYSTEM/root override file permissions; Windows ACL verification is only as good as `icacls` output and was
  validated on the owner's machine, not exhaustively across Windows versions or domain policies.
* Passphrase strength is policy-checked for length only; the stdin prompt does not suppress echo.
* The 128 MiB / 3 / 4 default is the wallet's; no hardware-specific tuning or HSM/TPM binding.
* No key rotation, backup/escrow or multi-party design; a lost passphrase is unrecoverable.
* The plaintext `qcb-keygen mldsa-v2` command (#106) still exists for tests and must not be used for production keys.
* The scheduler still receives `operator_secret_key_hex` in its request body (#105). **Key-file encryption does not fix that**; it is
  a separate blocking security workstream.
* No production validator keys are generated by this work.
