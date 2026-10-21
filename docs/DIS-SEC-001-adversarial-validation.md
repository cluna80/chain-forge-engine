# DIS-SEC-001: Assurance and Adversarial Validation

**Status:** Complete v0.1  
**Branch:** dis-sec-004  
**Test file:** `dis-core/tests/adversarial.rs`

---

## Scope

33 labeled attack scenarios against the DIS-KS-V1 stack. Every test must
produce a specific `Err(VerifyError::*)` — a green run proves the system
rejects all attacks cleanly.

---

## Attack Coverage

### Signature Forgery
| # | Attack | Expected error |
|---|--------|---------------|
| 1 | Completely forged signature (wrong secret key) | `Signature` |
| 2 | Bit-flip in signature bytes | `Signature` |
| 3 | Signature over a different transcript (wrong message) | `Signature` |
| 10 | Key substitution — swap public key in proof | `Signature` |
| 32 | Malformed/truncated public key in proof | `Signature` |

### Replay and Challenge Integrity
| # | Attack | Expected error |
|---|--------|---------------|
| 4 | Same challenge presented twice | `Replay` |
| 5 | Cross-RP challenge replay (RP-A challenge → RP-B) | `Audience` |
| 21 | Phantom challenge (challenge_id never issued) | `Replay` |
| 19 | Tampered resource_id after signing | `Challenge` |
| 20 | Tampered nonce after signing | `Challenge` |
| 31 | operation_digest swapped after signing | `Challenge` |

### Audience and Policy
| # | Attack | Expected error |
|---|--------|---------------|
| 6 | Wrong `rp_id` in request | `Audience` |
| 7 | Wrong `rp_origin` in request | `Audience` |
| 33 | Wrong `policy_id` in request | `Audience` |

### Time
| # | Attack | Expected error |
|---|--------|---------------|
| 8 | Expired request (`now >= expires_at`) | `Time` |
| 9 | Not-yet-valid request (`now < issued_at`) | `Time` |

### Authorization and Key Management
| # | Attack | Expected error |
|---|--------|---------------|
| 11 | Unenrolled key | `Unauthorized` |
| 12 | Revoked key | `Revoked` |
| 13 | Old key after rotation | `Revoked` |
| 14 | Unauthorized resource (not in grants) | `Unauthorized` |
| 15 | Unauthorized action (not in grants) | `Unauthorized` |
| 16 | Scope injection (extra scope not in grants) | `Unauthorized` |
| 17 | Empty scopes | `Unauthorized` |

### Downgrade
| # | Attack | Expected error |
|---|--------|---------------|
| 18 | `suite_id` below `min_suite_id` at issue | `DowngradedSuite` |

### Delegation Chain
| # | Attack | Expected error |
|---|--------|---------------|
| 22 | Agent exceeds delegated scopes | `DelegationInvalid` |
| 23 | Expired delegation link | `DelegationInvalid` |
| 24 | Chain depth > `MAX_CHAIN_DEPTH` (4) | `DelegationInvalid` |
| 25 | Forged delegation signature (wrong delegator key) | `DelegationInvalid` |
| 26 | High-risk action without `approve_challenge()` | `HumanApprovalRequired` |
| 27 | `max_uses` exhausted on second use | `DelegationUsesExhausted` |
| 28 | Agent key enrolled directly — self-delegation sig mismatch | `DelegationInvalid` |
| 29 | Scope widening mid-chain (link 2 wider than link 1) | `DelegationInvalid` |

### Recovery
| # | Attack | Expected error / outcome |
|---|--------|--------------------------|
| 30 | Stolen device — revoked key rejected, new key accepted | `Revoked` for old, `Ok` for new |

---

## Return Gates (before production claims)

- [ ] Independent third-party review of the adversarial suite for completeness
- [ ] Fuzz testing of `canonical_request` encoding with arbitrary bytes
- [ ] Timing side-channel analysis of signature verification path
- [ ] Test coverage for concurrent replay (race condition on `pending` map)
- [ ] Cross-platform conformance: run these vectors against non-Rust implementations
- [ ] Formal threat model document mapping each attack to the mitigating control
