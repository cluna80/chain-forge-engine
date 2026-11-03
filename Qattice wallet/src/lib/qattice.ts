export const UQCB = 1_000_000;
/** Genesis chain id. Override with VITE_CHAIN_ID only when the node is not qcb-testnet-4node. */
export const CHAIN_ID: string =
  (typeof import.meta !== "undefined" &&
    (import.meta as { env?: Record<string, string> }).env?.VITE_CHAIN_ID) ||
  "qcb-testnet-4node";
export const ADDRESS = "qcb1pq1k4rm7w4llet9h0lder2charm";
export const TX_DOMAIN = "chain-forge/pq-tx/v1";

// ---------------------------------------------------------------------------
// Node connectivity
// ---------------------------------------------------------------------------

/** Base URL of a running Qattice node. Set VITE_NODE_URL to override. */
export const NODE_URL: string | null =
  (typeof import.meta !== "undefined" &&
    (import.meta as { env?: Record<string, string> }).env?.VITE_NODE_URL) ||
  null;

export type NodeIdentity = {
  address: string;
  registered: boolean;
  tier: string | null;
  attestation_count: number;
  attested_by: string[];
  frozen: boolean;
};

export type NodeAccount = {
  address: string;
  nonce: number;
  balances: Record<string, number>;
  tier?: string | null;
  attestation_count?: number;
  attested_by?: string[];
};

export type NodeProbe = {
  reachable: boolean;
  identity: NodeIdentity | null;
  account: NodeAccount | null;
  error: string | null;
};

export type NodeTxResult =
  | { ok: true; tx_id: string }
  | { ok: false; error: string };

async function nodeCall<T>(path: string): Promise<{ status: number; data: T | null }> {
  if (!NODE_URL) return { status: 0, data: null };
  try {
    const res = await fetch(`${NODE_URL}${path}`, {
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return { status: res.status, data: null };
    return { status: res.status, data: (await res.json()) as T };
  } catch {
    return { status: 0, data: null };
  }
}

async function nodeGet<T>(path: string): Promise<T | null> {
  const res = await nodeCall<T>(path);
  return res.status === 200 ? res.data : null;
}

export async function fetchNodeIdentity(address: string): Promise<NodeIdentity | null> {
  return nodeGet<NodeIdentity>(`/api/identity/${address}`);
}

export async function fetchNodeAccount(address: string): Promise<NodeAccount | null> {
  return nodeGet<NodeAccount>(`/api/accounts/${address}`);
}

/** 404 is reachable (address missing). status 0 is a network failure. */
export async function probeNode(address: string): Promise<NodeProbe> {
  if (!NODE_URL) {
    return { reachable: false, identity: null, account: null, error: "Set VITE_NODE_URL to connect to a live node." };
  }
  const [identity, account] = await Promise.all([
    nodeCall<NodeIdentity>(`/api/identity/${address}`),
    nodeCall<NodeAccount>(`/api/accounts/${address}`),
  ]);
  if (identity.status === 0 && account.status === 0) {
    return { reachable: false, identity: null, account: null, error: `Cannot reach node at ${NODE_URL}` };
  }
  const missing = identity.status === 404 && account.status === 404;
  return {
    reachable: true,
    identity: identity.status === 200 ? identity.data : null,
    account: account.status === 200 ? account.data : null,
    error: missing ? "This address is not on the node yet." : null,
  };
}

export async function submitNodeTx(body: Record<string, unknown>): Promise<NodeTxResult> {
  if (!NODE_URL) return { ok: false, error: "No node URL configured (set VITE_NODE_URL)." };
  try {
    const res = await fetch(`${NODE_URL}/api/tx`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await res.text();
    let json: Record<string, unknown> = {};
    try { json = JSON.parse(text) as Record<string, unknown>; } catch { /* ignore */ }
    if (!res.ok) {
      const msg = (json.error as string) || (json.message as string) || text.slice(0, 120);
      return { ok: false, error: msg };
    }
    const tx_id = (json.tx_id as string) || (json.id as string) || "submitted";
    return { ok: true, tx_id };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}
export const DIS_DOMAIN = "DIS-KS-V1";
export const GAS_LIMIT = 80_000;
export const ATTESTATION_QUORUM = 3;
export const SESSION_MS = 15 * 60 * 1000;

export type Tab = "home" | "stone" | "move" | "agents" | "spec";
export type Tier = "provisional" | "verified";
export type SpecGroup = "phone" | "next" | "gate";

export type Vendor = {
  id: string;
  name: string;
  origin: string;
  grants: string[];
  fingerprint: string;
  status: "active" | "rotated";
};

export type Challenge = {
  id: string;
  rpId: string;
  origin: string;
  resource: string;
  action: string;
  scopes: string[];
  nonce: string;
  exp: number;
  kind: "holder" | "delegated";
  agent?: string;
  spendUqcb?: number;
};

export type Proof = {
  challengeId: string;
  vendorId: string;
  fingerprint: string;
  digest: string;
  /** mldsa65:<hex> over the DIS-KS-V1 transcript, signed by the chain account key. */
  signature?: string;
  at: number;
  resource: string;
  action: string;
};

export type Session = {
  id: string;
  vendorId: string;
  vendorName: string;
  origin: string;
  resource: string;
  action: string;
  scopes: string[];
  fingerprint: string;
  digest: string;
  openedAt: number;
  exp: number;
};

export type Activity = {
  id: string;
  title: string;
  detail: string;
  at: number;
};

export type Agent = {
  id: string;
  name: string;
  scopes: string[];
  maxUses: number;
  uses: number;
  spendCapUqcb: number;
  spentUqcb: number;
  humanGate: boolean;
  status: "active" | "revoked";
};

export type AgentAsk = {
  id: string;
  agentId: string;
  resource: string;
  action: string;
  scopes: string[];
  spendUqcb: number;
};

export type Sponsored =
  | {
      id: string;
      kind: "agent";
      name: string;
      purpose: string;
      spendCapUqcb: number;
      status: "active" | "revoked";
    }
  | {
      id: string;
      kind: "contract";
      name: string;
      purpose: string;
      status: "active" | "revoked";
    };

export type SpecItem = {
  id: string;
  group: SpecGroup;
  title: string;
  detail: string;
  surface?: Tab;
  rehearsal?: Rehearsal;
};

export type Rehearsal =
  | "send"
  | "sign"
  | "reject"
  | "rotate"
  | "approve"
  | "verified"
  | "session"
  | "participate"
  | "sponsor";

export function formatQcb(uqcb: number) {
  const sign = uqcb < 0 ? "-" : "";
  const v = Math.abs(Math.trunc(uqcb));
  const whole = Math.floor(v / UQCB);
  const frac = String(v % UQCB).padStart(6, "0");
  return `${sign}${whole.toLocaleString("en-US")}.${frac}`;
}

export function formatUqcb(uqcb: number) {
  return `${Math.trunc(uqcb).toLocaleString("en-US")} uQCB`;
}

export function shortAddress(address: string) {
  if (address.length < 18) return address;
  return `${address.slice(0, 10)}…${address.slice(-4)}`;
}

export function fingerprint(seed: string) {
  let h = 2166136261;
  for (const c of seed) h = Math.imul(h ^ c.charCodeAt(0), 16777619);
  return (h >>> 0).toString(16).padStart(8, "0");
}

export function uid(prefix: string) {
  return `${prefix}-${Math.random().toString(36).slice(2, 8)}`;
}

export async function sha256Hex(message: string) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(message));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function txPreimage(bodyJson: string) {
  return `${TX_DOMAIN}\n${CHAIN_ID}\n${bodyJson}`;
}

/** serde_json externally tagged TxBody::Transfer { to, denom, amount }. */
export function transferBodyJson(to: string, amountUqcb: number) {
  return JSON.stringify({ Transfer: { to, denom: "uqcb", amount: amountUqcb } });
}

export function disPreimage(c: Challenge, vendorFingerprint: string) {
  return [
    DIS_DOMAIN,
    c.rpId,
    c.origin,
    c.resource,
    c.action,
    c.scopes.join(","),
    c.nonce,
    String(c.exp),
    vendorFingerprint,
  ].join("\n");
}

export function reviewChallenge(c: Challenge, vendors: Vendor[], now: number) {
  const reasons: string[] = [];
  const vendor = vendors.find((v) => v.id === c.rpId && v.status === "active");
  if (now > c.exp) reasons.push("Challenge expired. DIS challenges are single-use and live about 60 seconds.");
  if (!vendor) {
    reasons.push("No active key for this relying party. Provision that vendor before signing.");
  } else if (vendor.origin !== c.origin) {
    reasons.push("Audience does not match the enrolled origin. Cross-vendor reuse is rejected.");
  } else {
    const outside = c.scopes.filter((s) => !vendor.grants.includes(s));
    if (outside.length) {
      reasons.push(`Scope is not in this vendor’s grant: ${outside.join(", ")}.`);
    }
  }
  if (c.kind === "delegated" && (c.spendUqcb ?? 0) > 0) {
    reasons.push("Delegated spend needs the human-approval gate on the Agents desk, not a blind Stone signature.");
  }
  return { ok: reasons.length === 0, reasons, vendor };
}

export function parseChallenge(raw: string, now: number): Challenge | { error: string } {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return { error: "That is not JSON. Paste the vendor challenge object." };
  }
  if (!data || typeof data !== "object") return { error: "Challenge must be a JSON object." };
  const o = data as Record<string, unknown>;
  const rpId = str(o.rp_id ?? o.rpId ?? o.vendor_id ?? o.vendorId);
  const origin = str(o.origin ?? o.rp_origin ?? o.audience);
  const resource = str(o.resource ?? o.resource_id ?? o.resourceId);
  const action = str(o.action) || "read";
  const nonce = str(o.nonce ?? o.challenge_id ?? o.id) || uid("ch");
  if (!rpId || !origin || !resource) {
    return { error: "Need rp_id (or vendor_id), origin, and resource." };
  }
  const scopesRaw = o.scopes ?? o.scope;
  const scopes = Array.isArray(scopesRaw)
    ? scopesRaw.map(String)
    : typeof scopesRaw === "string" && scopesRaw
      ? scopesRaw.split(/[,\s]+/).filter(Boolean)
      : [action];
  let exp = now + 60_000;
  const expRaw = o.exp ?? o.expires ?? o.expiry;
  if (typeof expRaw === "number") exp = expRaw < 10_000_000_000 ? expRaw * 1000 : expRaw;
  else if (typeof expRaw === "string") {
    const n = Date.parse(expRaw);
    if (!Number.isNaN(n)) exp = n;
  }
  return {
    id: str(o.id) || uid("ch"),
    rpId,
    origin,
    resource,
    action,
    scopes,
    nonce,
    exp,
    kind: o.kind === "delegated" ? "delegated" : "holder",
    agent: str(o.agent) || undefined,
    spendUqcb: typeof o.spend_uqcb === "number" ? o.spend_uqcb : undefined,
  };
}

function str(v: unknown) {
  return typeof v === "string" ? v.trim() : "";
}

export function freshChallenge(now: number): Challenge {
  return {
    id: uid("ch"),
    rpId: "docs",
    origin: "https://docs.qattice.test",
    resource: "document:001",
    action: "read",
    scopes: ["document:read"],
    nonce: uid("n"),
    exp: now + 60_000,
    kind: "holder",
  };
}

export const SPEC: SpecItem[] = [
  {
    id: "provision",
    group: "phone",
    title: "Provision a vendor key",
    detail:
      "The test APK already takes a vendor id and origin and generates an ML-DSA-65 key through the JNI bridge. Keep that. Do not turn it into one global login key.",
    surface: "stone",
  },
  {
    id: "scan",
    group: "phone",
    title: "Scan or paste a challenge",
    detail:
      "QR scan and a paste field exist. The sophisticated app must parse the challenge into bindings before anything is signed — the phone today drops raw JSON into a box.",
    surface: "stone",
  },
  {
    id: "local-sign",
    group: "phone",
    title: "Sign on the device",
    detail:
      "Private keys stay in Android Keystore (AES-256-GCM). The node and the vendor receive a proof, never the key. This rehearsal does not replace that custody.",
    surface: "stone",
  },
  {
    id: "server-auth",
    group: "phone",
    title: "Vendor server round-trip",
    detail:
      "enroll → issue challenge → verify, via VendorServerClient. Production still needs authenticated enrollment, not enroll_test_key.",
    surface: "stone",
  },
  {
    id: "chain-account",
    group: "next",
    title: "Separate chain account",
    detail:
      "chain-forge-wallet already derives a qcb1pq address from the ML-DSA-65 public key and signs transfers. The Android UI has no balance, nonce, or send. The chain key and the per-vendor DIS keys are different keys.",
    surface: "home",
    rehearsal: "send",
  },
  {
    id: "envelope",
    group: "next",
    title: "Signed transaction envelope",
    detail:
      "Prehash is SHA-256 of chain-forge/pq-tx/v1, the chain id, and the canonical body. ML-DSA-65 signs that 32-byte digest. POST /api/tx gets sig_scheme MlDsa, pq_signatures [mldsa65:hex], and pq_public_key. The Ed25519 signature field is omitted.",
    surface: "move",
    rehearsal: "send",
  },
  {
    id: "nonce",
    group: "next",
    title: "Nonce, chain id, denom",
    detail:
      "Nonce must equal the account nonce. Replay and gaps over 100 are rejected. Chain id is bound into the signature so a testnet signature cannot ride onto another chain. Denom is uQCB. 1 QCB = 1,000,000 uQCB. Older samples still say uqrc; do not ship that name.",
    surface: "move",
    rehearsal: "send",
  },
  {
    id: "consent",
    group: "next",
    title: "Show bindings before sign",
    detail:
      "Audience, resource, action, scope, nonce, and expiry. Refuse expired challenges, wrong origin, and scopes outside the vendor grant. A 60-second single-use challenge is the doorway, not a session token.",
    surface: "stone",
    rehearsal: "sign",
  },
  {
    id: "session",
    group: "next",
    title: "Scoped session, not a login token",
    detail:
      "A good signature consumes the challenge and opens one vendor grant. That grant cannot be replayed at another vendor, and it cannot move QCB. Rotating that vendor’s key ends only that session.",
    surface: "stone",
    rehearsal: "session",
  },
  {
    id: "unlink",
    group: "next",
    title: "Unlinkable vendor keys",
    detail:
      "DIS-PRIV-001: each relying party gets its own public key. Rotating or revoking one vendor must not move the others (DIS-KS-002). The UI should show the fingerprints side by side so that is obvious.",
    surface: "stone",
    rehearsal: "rotate",
  },
  {
    id: "tier",
    group: "next",
    title: "Identity tier is not a login",
    detail:
      "A successful DIS sign-in does not prove personhood. Provisional becomes Verified only after an attestation quorum of 3. Verified unlocks personhood-weighted participation, activity rewards, governance, and charmed-agent sponsorship. Liveness is periodic participation, not a badge you keep forever.",
    surface: "home",
    rehearsal: "verified",
  },
  {
    id: "participate",
    group: "next",
    title: "Verified participation",
    detail:
      "Activity rewards and governance stay closed until the attestation quorum. One verified human, one vote. The weight is personhood, not the QCB balance. A vendor session does not unlock either.",
    surface: "home",
    rehearsal: "participate",
  },
  {
    id: "sponsor",
    group: "next",
    title: "SponsorID on agents and contracts",
    detail:
      "A verified human can sponsor a charmed agent or a contract. The sponsor id is the qcb1pq account, so the chain can hold that human accountable. A provisional identity and a DIS login cannot sponsor. This rehearsal records the intent. It does not deploy to the devnet.",
    surface: "agents",
    rehearsal: "sponsor",
  },
  {
    id: "agents",
    group: "next",
    title: "Delegated agents",
    detail:
      "Depth at most 4. Scopes may only narrow. max_uses is counted. High-risk and spend actions stop on a human-approval gate. Spending limits are part of the design; durable server enforcement is still a return gate.",
    surface: "agents",
    rehearsal: "approve",
  },
  {
    id: "reject",
    group: "next",
    title: "Refuse a bad challenge in the UI",
    detail:
      "Forged, expired, cross-audience, and scope-injected challenges are already rejected by the protocol tests. The wallet should explain the refusal before the user taps Sign, instead of returning a raw error string.",
    surface: "stone",
    rehearsal: "reject",
  },
  {
    id: "hsm",
    group: "gate",
    title: "Keystore is not an audit",
    detail:
      "AES-256-GCM in Android Keystore is the right direction. Production still replaces DemoWallet with an HSM or OS-backed ceremony, and the transcript format still wants an independent review.",
  },
  {
    id: "recovery",
    group: "gate",
    title: "No recovery design yet",
    detail:
      "DIS-PQ-001 says return to wallet key recovery before production. Do not add a seed phrase that can resurrect a compromised key. Recovery has to issue a new key and preserve vendor continuity.",
  },
  {
    id: "tls",
    group: "gate",
    title: "Hybrid TLS and real enrollment",
    detail:
      "Vendor origins still need post-quantum hybrid TLS, and enrollment must be RP-authenticated. Chain transactions are ML-DSA-65. A Stone signature is the chain account over the DIS-KS-V1 transcript, not a per-vendor DIS key and not DIS-AUTH-V1.",
  },
];

export const REWARD_UQCB = 50_000;

export const PROPOSAL = {
  id: "personhood-cap",
  title: "Cap one human’s validator weight",
  detail: "A verified human’s vote is capped. Stake alone cannot raise that weight.",
};

export function seedVendors(): Vendor[] {
  return [
    {
      id: "docs",
      name: "Docs",
      origin: "https://docs.qattice.test",
      grants: ["document:read"],
      fingerprint: fingerprint("docs-seed"),
      status: "active",
    },
    {
      id: "merchant",
      name: "Merchant",
      origin: "https://pay.qattice.test",
      grants: ["payment:request"],
      fingerprint: fingerprint("merchant-seed"),
      status: "active",
    },
    {
      id: "agents",
      name: "Agent host",
      origin: "https://agents.qattice.test",
      grants: ["agent:spawn", "agent:spend"],
      fingerprint: fingerprint("agents-seed"),
      status: "active",
    },
  ];
}

export function seedAgents(): Agent[] {
  return [
    {
      id: "courier",
      name: "Courier",
      scopes: ["payment:request"],
      maxUses: 5,
      uses: 1,
      spendCapUqcb: 1_000_000,
      spentUqcb: 100_000,
      humanGate: true,
      status: "active",
    },
  ];
}
