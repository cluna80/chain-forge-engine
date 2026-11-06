# Scheduler settlement: affected clients and migration (PR #110)

Documentation only. Describes what PR #110 changes for anyone who called the scheduler's settlement API, and how to move to the
new flow. Written against PR #110 head `2808a90`.

## What changed
| Request | Before (`main`) | After #110 |
|---|---|---|
| `POST /scheduler/objectives/{id}/settle` | accepted `operator_secret_key_hex` in the body, signed in the scheduler, submitted | **410 Gone**, `{"error":"settle_endpoint_removed"}`. The body is never read. Same answer on every build and every chain. |
| `POST …/settle/prepare` | did not exist | public data in, unsigned claim transaction and a signing request out |
| `POST …/settle/submit` | did not exist | the **signed** transaction in; the scheduler checks it is exactly the stored claim, then forwards it to the node |
| any request carrying private-key material | not rejected | **400** `private_key_material_rejected`, before the body is parsed |
| default build (no `signing-v2`) `prepare`/`submit` | n/a | **501** `signing_unavailable`; the 410 and the key-material rejection still apply |

This is a **breaking change by design**: the old route is the vulnerability (a private key in an HTTP request body).

## Who is affected
1. **Any external script, cron job, `curl` command or operator tooling that POSTs to `…/settle`.** I found **no caller inside this
   repository** (searched the workspace crates, `scripts/`, the miner, wallet and verifier crates). The only references are
   documentation: `tests/devnet/results/pocd-e2e-2026-10-11.md` records an earlier manual use of the old route; that is historical
   evidence and is left as written. Callers outside the repository cannot be searched, so **operators must check their own tooling**.
2. **Operators on legacy (non-`qattice-v2`) chains.** `prepare` accepts only `signing_profile: "qattice-v2"` (422
   `unsupported_signing_profile` otherwise). There is **no scheduler-assisted settlement for a legacy chain after #110**, and there is
   no legacy fallback by design. Options: (a) keep running a pre-#110 scheduler, which keeps the key-in-body risk; (b) build and
   sign the claim transaction outside the scheduler with your own tooling; (c) move the chain to a `qattice-v2` genesis. This is a
   real limitation, not a solved case.
3. **Release builds without the `signing-v2` feature.** They answer `prepare`/`submit` with 501. The public-alpha build includes
   `signing-v2`.
4. **Anyone who ever sent a real operator key to the old route.** Treat that key as **exposed** to anything that could read the
   scheduler's traffic or request logs, and rotate it. The scheduler API has no TLS or authentication, so a key sent over a
   non-loopback network was readable on the wire.

## Migration to the new flow (v2 chains)
Prerequisites: scheduler and signer built with `--features signing-v2`; a chain whose genesis has `commitment_profile = "qattice-v2"`;
the operator's address in genesis `settlement_operators`; `treasury:pocd-research` funded; an operator wallet file (`qcb-wallet generate`).

1. **Prepare** (public data only). `operator_nonce` is the operator account's current nonce (`GET {node}/api/accounts/{operator}`).
   Send `carry_key: true` until the account's key is bound on chain (first use).
   ```
   curl -s -X POST $SCHEDULER/scheduler/objectives/$OBJ/settle/prepare -H 'content-type: application/json' -d '{
     "task_id":"…","reward_kind":"primary","recipient":"qcb1…","chain_id":"<node chain_id>",
     "operator_address":"qcb1pq…","operator_public_key_hex":"<1,952-byte public key, hex>",
     "carry_key":true,"operator_nonce":0,"disbursed_uqcb":0,"signing_profile":"qattice-v2"}' > prepared.json
   ```
2. **Sign** in a separate process that owns the key. The passphrase comes from `QCB_WALLET_PASSPHRASE` or stdin, **never** the command
   line (`--passphrase` is rejected). The signer recomputes the preimage itself and signs only a `ClaimResearchReward` from its own
   address, for the chain you tell it to expect.
   ```
   qcb-claim-signer --wallet operator.wallet.json --prepared prepared.json --expect-chain-id <node chain_id> [--max-amount-uqcb N] > signed.json
   ```
3. **Submit** the signed transaction. `node_url` must be `http://` or `https://`.
   ```
   curl -s -X POST $SCHEDULER/scheduler/objectives/$OBJ/settle/submit -H 'content-type: application/json' -d '{
     "claim_id":"…","chain_id":"<node chain_id>","signed_tx":{…from signed.json…},"node_url":"http://127.0.0.1:8080"}'
   ```

`prepare` is idempotent until the claim is submitted. A submitted claim cannot be prepared or submitted again (409).

## Error reference
| Status | `error` | Meaning |
|---|---|---|
| 400 | `private_key_material_rejected` | the body contained a key-like field name or a secret-key-sized value; nothing was stored or sent |
| 404 | `no_accepted_result`, `claim_not_found` | no accepted result for the task, or an unknown claim id |
| 409 | `claim_already_exists` | the claim is no longer pending |
| 410 | `settle_endpoint_removed` | the old route |
| 422 | `invalid_request`, `unsupported_signing_profile`, `unknown_reward_kind`, `policy_rejected`, `public_key_invalid`, `transaction_does_not_match_claim`, `signature_rejected` | the request or the signed transaction is not acceptable |
| 501 | `signing_unavailable` | the scheduler was built without `signing-v2` |
| 502 | `node_submission_failed` | the node did not accept the transaction |

## Known dependencies, and what is not known
Owner decision (2026-11-06): the HTTP 410 is the intended secure behaviour for Qattice v2. **Do not assume external operators are unaffected.**

**Known (searched every tracked file of the repository at PR #110 head `2808a90`):**
| Where | Dependency | Action |
|---|---|---|
| `tests/devnet/results/pocd-e2e-2026-10-11.md` | a historical record of two manual calls to the old route | none; it is evidence of what happened on 2026-10-11 and is left as written |
| `ROADMAP.md` (COS-PoCD-000/002 rows) | planned work says it will "reuse research reward settlement" | that work must use prepare / sign / submit; it must not be built on the old route |
| `docs/key-storage/*` | prose that mentions the old route as a blocking issue | closed by PR #110 once merged |
| workspace crates, `scripts/`, miner, verifier, wallet | **none**: no code calls the route | none |

**Not known (cannot be searched from the repository):** operator scripts, cron jobs, dashboards, CI jobs, runbooks and shell history on
machines outside this repository; other repositories; anything that talks to a deployed scheduler. The only evidence available is each
operator's own, so the checks below must be run by whoever operates a scheduler.

## Operator self-check (read-only; run before the upgrade)
Find anything that still sends the old request or a private key:
```bash
# Git Bash: tracked scripts and notes under your own folders (adjust the roots; -I skips binaries, -l lists files only)
grep -rIl --exclude-dir=target --exclude-dir=.git -E "operator_secret_key_hex|/settle([^/a-z_]|$)" /c/Dev /c/Users/"$USERNAME"/Documents 2>/dev/null
```
```powershell
# PowerShell equivalent
Get-ChildItem C:\Dev -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\\(target|\.git)\\' } |
  Select-String -Pattern 'operator_secret_key_hex','/settle(?![/a-z_])' -List | Select-Object -ExpandProperty Path
```
Also check any reverse proxy or scheduler access log you keep for `POST …/settle` (without `/prepare` or `/submit`). Any hit means a client
still needs the new flow. A client that gets `410` must treat it as permanent and must not retry.

## Required steps before the scheduler with this change is deployed
1. Inventory callers (self-check above) and list who owns each.
2. Tell every owner the old route returns 410 from the new scheduler build, and share this guide.
3. Treat every operator key that was ever sent to the old route as exposed; create a new wallet and register the new address in genesis
   `settlement_operators` (or, on a running chain, through the chain's own governance path; this guide does not change it).
4. Build the scheduler and `qcb-claim-signer` with `--features signing-v2`; rehearse prepare / sign / submit on a devnet first.
5. Only then deploy. **Rollback** is the previous scheduler build, which keeps the key-in-body route; use it only as a stop-gap and rotate
   the key again afterwards.
6. Record the date each caller was migrated. A caller that cannot migrate (for example a legacy, non-`qattice-v2` chain) has no
   scheduler-assisted path; that is a known loss of function, not a bug.

## Remaining limitations (unchanged by this document)
No TLS or authentication on the scheduler API; `node_url` is caller-supplied (SSRF risk); the key-material check is heuristic (the
structural guarantee is that no field or code path accepts a key); the signer holds the key in memory while signing; the wallet file
uses the legacy wallet container, not the `qattice-key` format of #109.
