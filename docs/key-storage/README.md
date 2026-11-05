# Encrypted key storage — operator guide (issue #107)

Design, threat model and file format: [`SPEC.md`](SPEC.md). Everything here needs the `signing-v2` cargo feature of
`chain-forge-keygen`. **Do not generate production validator keys with this build until the open items below are decided.**

## Create an encrypted key
```bash
printf '%s' 'a long passphrase of 12+ bytes' > /secure/place/pass.txt      # or: export QCB_KEY_PASSPHRASE=...
qcb-keygen key-new alice --out /secure/keys/alice.qkey.json --passphrase-file /secure/place/pass.txt
```
* The passphrase is **never** accepted on the command line (`--passphrase` is rejected). Sources: `--passphrase-file`,
  `QCB_KEY_PASSPHRASE`, or stdin.
* `--out` must be a new file. Its directory is created owner-only if missing (one level; the parent must exist). An existing
  directory must already be private; otherwise add `--harden-existing-dir`, which **changes that directory's permissions**.
* Default cost: Argon2id 128 MiB / 3 / 4 (the wallet's). `--kdf-memory-kib/--kdf-iterations/--kdf-parallelism` may raise or lower it
  within 19 MiB/2/1 .. 1 GiB/10/16; a file outside those bounds is refused on load.
* Only the 32-byte seed is stored (encrypted); the expanded key is regenerated in memory when needed.

## Check a key
`qcb-keygen key-check <file>` verifies permissions, decrypts, recomputes the public key and address, and prints only public
information.

## Migrate a plaintext key (from `qcb-keygen mldsa-v2` or the legacy `mldsa` output)
```bash
qcb-keygen key-migrate --from alice-plain.json --out /secure/keys/alice.qkey.json --passphrase-file /secure/place/pass.txt
qcb-keygen key-check /secure/keys/alice.qkey.json --passphrase-file /secure/place/pass.txt     # confirm it works
```
1. The old file is **never modified, deleted or printed** by the tool. The output must be a new file.
2. A `mldsa-v2` file with a seed becomes a seed-only key (the stored expanded key is dropped). A legacy `mldsa` file has no FIPS 204
   seed, so its expanded key is stored encrypted (`payload_kind = expanded-secret-key`); it still signs under signing v2.
3. After you have confirmed the new file works, **remove the old plaintext file yourself**, and any copies, backups, shell history or
   cloud-sync copies of it. Until then the key still exists in the clear.
Migration does not change any genesis, address, public key or signature rule.

## Permissions
* Unix: file `0600`, directory `0700`; load refuses anything looser (including a group/other-writable directory).
* Windows: protected DACL with exactly one allow ACE for the current user's SID on the file and the directory, **read back with
  `icacls /save` and verified**; load repeats the check. Administrators/SYSTEM can always override.

## Windows validation (BossKing, Git Bash)
```bash
cd /c/Dev/chain-forge-engine && git fetch origin feat/key-storage-hardening
git worktree add ../ks-wt origin/feat/key-storage-hardening          # skip if ks-wt already exists
cd /c/Dev/ks-wt && git log --oneline -1                              # paste this line together with the output
export CARGO_INCREMENTAL=0
cargo test -j 2 -p chain-forge-keygen --features signing-v2 -- --nocapture --test-threads=1
```
Expected on Windows (the `cfg(unix)` permission tests are not compiled there): `keygen_v2` 9, `keystore` 20, `keystore_cli` 9,
`keystore_windows` 7, all `0 failed`. Then look at the real ACLs yourself:
```bash
export QCB_KEY_PASSPHRASE='a long passphrase of 12+ bytes'
mkdir -p /c/Dev/ks-demo && cd /c/Dev/ks-demo
/c/Dev/cf-target2/debug/qcb-keygen.exe key-new demo --out /c/Dev/ks-demo/keys/demo.qkey.json --kdf-memory-kib 19456 --kdf-iterations 2 --kdf-parallelism 1
icacls /c/Dev/ks-demo/keys/demo.qkey.json      # expect exactly ONE entry: your account, (F)
icacls /c/Dev/ks-demo/keys                     # expect exactly ONE entry: your account, (OI)(CI)(F); no "(I)" inherited entries
cd /c/Dev/chain-forge-engine && rm -rf /c/Dev/ks-demo && git worktree remove --force ../ks-wt
```
(If the binary is not at that path, `cargo build -p chain-forge-keygen --features signing-v2` puts it under `$CARGO_TARGET_DIR/debug`.)

## Open items (not solved by this work)
Same-user malware and memory disclosure; Administrators/SYSTEM override; the stdin prompt does not hide input; passphrase strength
is length-checked only; no key rotation/backup; hedged-signing side channels on Windows untested; **the scheduler's
`operator_secret_key_hex` request-body exposure (#105) is a separate blocking workstream**; the plaintext `mldsa-v2` command still
exists for tests; wallet/scheduler/node do not read this format yet.
