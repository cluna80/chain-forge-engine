# Genesis profile decision record (DRAFT, awaiting owner confirmation)

Status: **proposed from the owner's message of 2026-11-04** ("My recommendation is a fresh-v2 genesis with the account leaf v2 (ACCT-LEAF-1) and the authority tree", re-sent as the decision on item 1 of the testnet blockers). Interpreted as approval in principle. Nothing is implemented; no production, state-root, signing, genesis or persistence change. Not merged.

## Decided in principle
- The public testnet launches on a **fresh-v2 genesis**: ACCT-LEAF-1 v2 account leaf plus the R2 authority tree, in one commitment profile. No in-place migration of existing devnets; legacy chains keep today's roots.
- Rationale: genesis cannot change after outside operators join. Choosing the profile now avoids a post-launch reset.

## Defaults I propose for Q1–Q3 (confirm or change)
| Q | Proposed answer | Consequence |
|---|---|---|
| Q1 tree layout | Option S: separate authority tree, root in the state tree as the single leaf `meta:authority_root/v1` | Second tree reuses `jmt.rs` with its own key-hash domain |
| Q2 account tier mirror | Drop on v2: identity record is the only source of tier; the account leaf carries no identity tier | Removes the E1 class on v2 chains |
| Q3 profile selection | Genesis field `commitment_profile`; **absent = legacy**; included in the genesis hash **only when present**, so legacy genesis hashes do not change | Adding the field is a genesis-format change; needs a version gate so legacy nodes refuse v2 genesis |

## Still undecided (not covered by the message)
Q4 live validator set (commit full vs digest), Q5 numeric bounds and where admission enforces them (including the `claim:{id}` role), Q6 whether `pop_verified` is cache or authoritative, Q7 persisted `*_uqrc` names, Q8 R5 manifest signing timing, and O8–O11 from the ACCT-LEAF-1 design (#82). Until Q5 is answered the encoder bounds in O8 cannot be adopted (audit §14).

## What this unblocks (each its own reviewed PR, owner authorization per step)
1. SC2-A permanent characterization tests (tests only).
2. O8 admission and genesis validators (needed under either profile).
3. SC2-C byte-level vectors and Python encoder for authority records (no Rust).
4. SC2-D restore-time re-derivation; SC2-E authority tree and v2 profile.
Windows confirmation before any ✅.
