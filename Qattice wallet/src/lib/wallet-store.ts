import { create } from "zustand";
import { persist } from "zustand/middleware";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { getAddress, getUnlocked, type WalletKeypair } from "@/lib/keypair-store";
import { mldsaSign } from "@/lib/mldsa";
import {
  GAS_LIMIT,
  type Activity,
  type Agent,
  type AgentAsk,
  type Challenge,
  type Proof,
  type Session,
  type Sponsored,
  REWARD_UQCB,
  SESSION_MS,
  type Rehearsal,
  type Tab,
  type Tier,
  type Vendor,
  disPreimage,
  fingerprint,
  freshChallenge,
  reviewChallenge,
  seedAgents,
  seedVendors,
  sha256Hex,
  txPreimage,
  uid,
  fetchNodeIdentity,
  fetchNodeAccount,
  probeNode,
  submitNodeTx,
  NODE_URL,
  transferBodyJson,
} from "@/lib/qattice";

type State = {
  hydrated: boolean;
  tab: Tab;
  moveMode: "send" | "receive";
  balanceUqcb: number;
  nonce: number;
  tier: Tier;
  attestations: number;
  attested_by: string[];
  nodeConnected: boolean | null;
  nodeError: string | null;
  vendors: Vendor[];
  challenges: Challenge[];
  agents: Agent[];
  sponsored: Sponsored[];
  ask: AgentAsk | null;
  activity: Activity[];
  proof: Proof | null;
  sessions: Session[];
  rehearsed: Rehearsal[];
  vote: "yes" | "no" | null;
  claimed: boolean;
  setHydrated: () => void;
  setTab: (tab: Tab) => void;
  setMoveMode: (mode: "send" | "receive") => void;
  reset: () => void;
  syncFromNode: () => Promise<void>;
  attest: () => Promise<{ ok: true; tx_id: string } | { ok: false; error: string }>;
  claim: () => { ok: true } | { ok: false; error: string };
  castVote: (choice: "yes" | "no") => { ok: true } | { ok: false; error: string };
  send: (to: string, amountUqcb: number) => Promise<{ ok: true; digest: string; submitted: boolean } | { ok: false; error: string }>;
  pushChallenge: (c: Challenge) => void;
  loadFresh: () => void;
  loadBad: (kind: "expired" | "audience" | "scope") => void;
  sign: (id: string) => Promise<{ ok: true } | { ok: false; error: string }>;
  useAccess: (id: string, scope: string) => { ok: true; detail: string } | { ok: false; error: string };
  endSession: (id: string) => void;
  reject: (id: string, reason: string) => void;
  provision: (id: string, origin: string, grants: string[]) => { ok: true } | { ok: false; error: string };
  rotate: (id: string) => void;
  approveAsk: () => { ok: true } | { ok: false; error: string };
  denyAsk: () => void;
  revokeAgent: (id: string) => void;
  addAgent: (name: string, scopes: string[], maxUses: number, spendCapUqcb: number) => { ok: true } | { ok: false; error: string };
  sponsor: (
    kind: "agent" | "contract",
    name: string,
    purpose: string,
    spendCapUqcb: number | null,
  ) => { ok: true } | { ok: false; error: string };
  revokeSponsored: (id: string) => void;
};

function nowStamp() {
  return Date.now();
}

function base(): Omit<
  State,
  | "setHydrated"
  | "setTab"
  | "setMoveMode"
  | "reset"
  | "syncFromNode"
  | "attest"
  | "claim"
  | "castVote"
  | "send"
  | "pushChallenge"
  | "loadFresh"
  | "loadBad"
  | "sign"
  | "useAccess"
  | "endSession"
  | "reject"
  | "provision"
  | "rotate"
  | "approveAsk"
  | "denyAsk"
  | "revokeAgent"
  | "addAgent"
  | "sponsor"
  | "revokeSponsored"
> {
  const now = nowStamp();
  return {
    hydrated: false,
    tab: "home",
    moveMode: "send",
    balanceUqcb: NODE_URL ? 0 : 12_480_000,
    nonce: NODE_URL ? 0 : 7,
    tier: "provisional",
    attestations: NODE_URL ? 0 : 1,
    attested_by: [],
    nodeConnected: null,
    nodeError: null,
    vendors: seedVendors(),
    challenges: [freshChallenge(now)],
    agents: seedAgents(),
    sponsored: [],
    ask: {
      id: "ask-seed",
      agentId: "courier",
      resource: "merchant:invoice:14",
      action: "pay",
      scopes: ["payment:request"],
      spendUqcb: 250_000,
    },
    activity: [
      {
        id: "act-seed",
        title: "Vendor key provisioned",
        detail: "docs · fingerprint from the phone test wallet’s shape",
        at: now - 1000 * 60 * 60 * 26,
      },
    ],
    proof: null,
    sessions: [],
    rehearsed: [],
    vote: null,
    claimed: false,
  };
}

function mark(list: Rehearsal[], key: Rehearsal) {
  return list.includes(key) ? list : [...list, key];
}


async function submitSigned(
  kp: WalletKeypair,
  nonce: number,
  bodyJson: string,
  id: string,
): Promise<{ ok: true; tx_id: string; signature: string } | { ok: false; error: string }> {
  let signature: string;
  try {
    const digest = sha256(new TextEncoder().encode(txPreimage(bodyJson)));
    const sig = await mldsaSign(digest, hexToBytes(kp.private_key));
    signature = bytesToHex(sig);
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
  if (!NODE_URL) return { ok: true, tx_id: id, signature };
  const result = await submitNodeTx({
    id,
    sender: kp.address,
    nonce,
    gas_limit: GAS_LIMIT,
    body: JSON.parse(bodyJson) as unknown,
    sig_scheme: "MlDsa",
    pq_signatures: [`mldsa65:${signature}`],
    pq_public_key: kp.public_key,
  });
  if (!result.ok) return result;
  return { ok: true, tx_id: result.tx_id, signature };
}

export const useWallet = create<State>()(
  persist(
    (set, get) => ({
      ...base(),
      setHydrated: () => set({ hydrated: true }),
      setTab: (tab) => set({ tab }),
      setMoveMode: (moveMode) => set({ moveMode }),
      reset: () => set({ ...base(), hydrated: true }),
      syncFromNode: async () => {
        const probe = await probeNode(getAddress());
        if (!probe.reachable) {
          set({ nodeConnected: false, nodeError: probe.error });
          return;
        }
        const update: Partial<State> = { nodeConnected: true, nodeError: probe.error };
        if (probe.account) {
          const raw = probe.account.balances?.uqcb ?? 0;
          if (Number.isSafeInteger(raw)) update.balanceUqcb = raw;
          else update.nodeError = "Node balance is outside the safe integer range.";
          update.nonce = probe.account.nonce;
          if (!probe.identity && probe.account.tier) update.tier = probe.account.tier.toLowerCase() as Tier;
          if (probe.account.attestation_count != null) update.attestations = probe.account.attestation_count;
        } else {
          update.balanceUqcb = 0;
          update.nonce = 0;
          update.tier = "provisional";
          update.attestations = 0;
        }
        if (probe.identity) {
          update.attestations = probe.identity.attestation_count;
          update.attested_by = probe.identity.attested_by;
          update.tier = probe.identity.tier ? (probe.identity.tier.toLowerCase() as Tier) : "provisional";
        }
        set(update);
      },
      attest: async () => {
        const s = get();
        if (s.tier === "verified") return { ok: false, error: "Already verified." };
        const kp = getUnlocked();
        if (!kp) return { ok: false, error: "Unlock the wallet before signing." };
        if (!NODE_URL) {
          return { ok: false, error: "Set VITE_NODE_URL. Attestation is a chain transaction, not a local rehearsal." };
        }
        const identity = await fetchNodeIdentity(kp.address);
        let nonce = s.nonce;
        const account = await fetchNodeAccount(kp.address);
        if (account) nonce = account.nonce;
        if (!identity?.registered) {
          const reg = await submitSigned(kp, nonce, '"RegisterIdentity"', `reg-${kp.address}-${nonce}`);
          if (!reg.ok) {
            const already =
              reg.error.includes("already committed") ||
              reg.error.includes("replay not permitted") ||
              reg.error.includes("registered");
            if (!already) return { ok: false, error: `RegisterIdentity failed: ${reg.error}` };
          } else {
            nonce += 1;
            await new Promise((r) => setTimeout(r, 1500));
            const next = await fetchNodeAccount(kp.address);
            if (next) nonce = next.nonce;
          }
        }
        const bodyJson = JSON.stringify({ Attest: { claimant_id: kp.address } });
        const result = await submitSigned(kp, nonce, bodyJson, `attest-${kp.address}-${nonce}`);
        if (!result.ok) return result;
        set({
          nonce: nonce + 1,
          activity: [
            {
              id: uid("act"),
              title: "Attest tx submitted",
              detail: `tx ${result.tx_id} · mldsa65 ${result.signature.slice(0, 16)}`,
              at: nowStamp(),
            },
            ...get().activity,
          ],
        });
        setTimeout(() => void get().syncFromNode(), 1500);
        return result;
      },
      claim: () => {
        const s = get();
        if (s.tier !== "verified") return { ok: false, error: "Provisional identities cannot claim." };
        if (s.claimed) return { ok: false, error: "Already claimed in this rehearsal." };
        set({
          claimed: true,
          balanceUqcb: s.balanceUqcb + REWARD_UQCB,
          rehearsed: mark(s.rehearsed, "participate"),
          activity: [
            {
              id: uid("act"),
              title: "Activity reward claimed",
              detail: `${REWARD_UQCB.toLocaleString("en-US")} uQCB · verified participation, not a vendor login`,
              at: nowStamp(),
            },
            ...s.activity,
          ],
        });
        return { ok: true };
      },
      castVote: (choice) => {
        const s = get();
        if (s.tier !== "verified") return { ok: false, error: "Provisional identities cannot vote." };
        if (s.vote) return { ok: false, error: "This proposal already has your vote." };
        set({
          vote: choice,
          rehearsed: mark(s.rehearsed, "participate"),
          activity: [
            {
              id: uid("act"),
              title: "Governance vote cast",
              detail: `${choice} · one human, one vote · not weighted by the QCB balance`,
              at: nowStamp(),
            },
            ...s.activity,
          ],
        });
        return { ok: true };
      },
      send: async (to, amountUqcb) => {
        const s = get();
        const dest = to.trim();
        if (!dest.startsWith("qcb1")) return { ok: false, error: "Recipient must be a qcb1 address." };
        const kp = getUnlocked();
        if (!kp) return { ok: false, error: "Unlock the wallet before signing." };
        if (dest === kp.address) return { ok: false, error: "That is this wallet." };
        if (!Number.isInteger(amountUqcb) || amountUqcb <= 0) {
          return { ok: false, error: "Amount must be a positive whole number of uQCB." };
        }
        if (NODE_URL && amountUqcb > s.balanceUqcb) return { ok: false, error: "Balance is short." };
        let nonce = s.nonce;
        if (NODE_URL) {
          const account = await fetchNodeAccount(kp.address);
          if (account) nonce = account.nonce;
        }
        const bodyJson = transferBodyJson(dest, amountUqcb);
        const signed = await submitSigned(kp, nonce, bodyJson, `xfer-${nonce}-${uid("tx")}`);
        if (!signed.ok) return signed;
        if (!NODE_URL) {
          set({
            rehearsed: mark(s.rehearsed, "send"),
            activity: [
              {
                id: uid("act"),
                title: "Transfer signed, not submitted",
                detail: `${amountUqcb.toLocaleString("en-US")} uQCB → ${dest} · set VITE_NODE_URL to broadcast`,
                at: nowStamp(),
              },
              ...s.activity,
            ],
          });
          return { ok: true, digest: signed.signature, submitted: false };
        }
        set({
          balanceUqcb: s.balanceUqcb - amountUqcb,
          nonce: nonce + 1,
          rehearsed: mark(s.rehearsed, "send"),
          activity: [
            {
              id: uid("act"),
              title: "Transfer submitted",
              detail: `${amountUqcb.toLocaleString("en-US")} uQCB → ${dest} · tx ${signed.tx_id}`,
              at: nowStamp(),
            },
            ...s.activity,
          ],
        });
        setTimeout(() => void get().syncFromNode(), 1500);
        return { ok: true, digest: signed.signature, submitted: true };
      },
      pushChallenge: (c) => set({ challenges: [c, ...get().challenges.filter((x) => x.id !== c.id)] }),
      loadFresh: () => {
        const c = freshChallenge(nowStamp());
        set({ challenges: [c, ...get().challenges] });
      },
      loadBad: (kind) => {
        const now = nowStamp();
        const c = freshChallenge(now);
        if (kind === "expired") c.exp = now - 5_000;
        if (kind === "audience") c.origin = "https://other.vendor.test";
        if (kind === "scope") c.scopes = ["document:read", "admin:write"];
        c.id = uid("bad");
        set({ challenges: [c, ...get().challenges] });
      },
      sign: async (id) => {
        const s = get();
        const c = s.challenges.find((x) => x.id === id);
        if (!c) return { ok: false, error: "Challenge is gone." };
        const review = reviewChallenge(c, s.vendors, nowStamp());
        if (!review.ok || !review.vendor) return { ok: false, error: review.reasons[0] ?? "Refused." };
        const kp = getUnlocked();
        if (!kp) return { ok: false, error: "Unlock the wallet before signing." };
        const transcript = disPreimage(c, review.vendor.fingerprint);
        const digest = await sha256Hex(transcript);
        let signature: string;
        try {
          const sig = await mldsaSign(new TextEncoder().encode(transcript), hexToBytes(kp.private_key));
          signature = `mldsa65:${bytesToHex(sig)}`;
        } catch (e) {
          return { ok: false, error: e instanceof Error ? e.message : String(e) };
        }
        const proof: Proof = {
          challengeId: c.id,
          vendorId: review.vendor.id,
          fingerprint: review.vendor.fingerprint,
          digest,
          signature,
          at: nowStamp(),
          resource: c.resource,
          action: c.action,
        };
        const opened = nowStamp();
        const session: Session = {
          id: uid("ses"),
          vendorId: review.vendor.id,
          vendorName: review.vendor.name,
          origin: review.vendor.origin,
          resource: c.resource,
          action: c.action,
          scopes: c.scopes,
          fingerprint: review.vendor.fingerprint,
          digest,
          openedAt: opened,
          exp: opened + SESSION_MS,
        };
        set({
          proof,
          sessions: [session, ...s.sessions.filter((x) => x.vendorId !== session.vendorId)],
          challenges: s.challenges.filter((x) => x.id !== id),
          rehearsed: mark(s.rehearsed, "sign"),
          activity: [
            {
              id: uid("act"),
              title: "Session opened",
              detail: `${review.vendor.name} · ${c.scopes.join(", ")} · chain-key ML-DSA over DIS-KS-V1, not a vendor key`,
              at: opened,
            },
            ...s.activity,
          ],
        });
        return { ok: true };
      },
      useAccess: (id, scope) => {
        const s = get();
        const session = s.sessions.find((x) => x.id === id);
        if (!session) return { ok: false, error: "Session is gone." };
        if (nowStamp() > session.exp) return { ok: false, error: "Grant ended. Ask the vendor for a new challenge." };
        if (!session.scopes.includes(scope)) {
          return { ok: false, error: `This ${session.vendorName} session cannot use ${scope}.` };
        }
        set({
          rehearsed: mark(s.rehearsed, "session"),
          activity: [
            {
              id: uid("act"),
              title: "Vendor access",
              detail: `${session.vendorName} · ${session.resource} · ${scope}`,
              at: nowStamp(),
            },
            ...s.activity,
          ],
        });
        return {
          ok: true,
          detail: `${session.vendorName} allowed ${scope} on ${session.resource}. The chain balance did not move.`,
        };
      },
      endSession: (id) => {
        const s = get();
        const session = s.sessions.find((x) => x.id === id);
        if (!session) return;
        set({
          sessions: s.sessions.filter((x) => x.id !== id),
          activity: [
            {
              id: uid("act"),
              title: "Session ended",
              detail: `${session.vendorName} · other vendors were not signed out`,
              at: nowStamp(),
            },
            ...s.activity,
          ],
        });
      },
      reject: (id, reason) => {
        const s = get();
        const c = s.challenges.find((x) => x.id === id);
        if (!c) return;
        set({
          challenges: s.challenges.filter((x) => x.id !== id),
          rehearsed: mark(s.rehearsed, "reject"),
          activity: [
            {
              id: uid("act"),
              title: "Challenge refused",
              detail: `${c.rpId} · ${reason}`,
              at: nowStamp(),
            },
            ...s.activity,
          ],
        });
      },
      provision: (id, origin, grants) => {
        const clean = id.trim().toLowerCase();
        if (!/^[a-z][a-z0-9-]{1,24}$/.test(clean)) {
          return { ok: false, error: "Vendor id: letters, numbers, hyphen. 2–25 characters." };
        }
        if (!origin.startsWith("https://")) return { ok: false, error: "Origin must be https." };
        if (!grants.length) return { ok: false, error: "Add at least one scope grant." };
        const s = get();
        if (s.vendors.some((v) => v.id === clean)) return { ok: false, error: "That vendor already has a key." };
        const vendor: Vendor = {
          id: clean,
          name: clean,
          origin: origin.trim(),
          grants,
          fingerprint: fingerprint(`${clean}-${nowStamp()}`),
          status: "active",
        };
        set({
          vendors: [...s.vendors, vendor],
          activity: [
            {
              id: uid("act"),
              title: "Vendor provisioned",
              detail: `${clean} · ${vendor.fingerprint} · not shared with other vendors`,
              at: nowStamp(),
            },
            ...s.activity,
          ],
        });
        return { ok: true };
      },
      rotate: (id) => {
        const s = get();
        const next = fingerprint(`${id}-rot-${nowStamp()}`);
        set({
          vendors: s.vendors.map((v) =>
            v.id === id ? { ...v, fingerprint: next, status: "active" as const } : v,
          ),
          sessions: s.sessions.filter((ses) => ses.vendorId !== id),
          rehearsed: mark(s.rehearsed, "rotate"),
          activity: [
            {
              id: uid("act"),
              title: "Vendor key rotated",
              detail: `${id} · new fingerprint ${next}. That vendor’s session ended. Others were not touched.`,
              at: nowStamp(),
            },
            ...s.activity,
          ],
        });
      },
      approveAsk: () => {
        const s = get();
        const ask = s.ask;
        if (!ask) return { ok: false, error: "Nothing is waiting." };
        const agent = s.agents.find((a) => a.id === ask.agentId && a.status === "active");
        if (!agent) return { ok: false, error: "Agent is not active." };
        if (agent.uses >= agent.maxUses) return { ok: false, error: "max_uses is exhausted." };
        if (agent.spentUqcb + ask.spendUqcb > agent.spendCapUqcb) {
          return { ok: false, error: "Spend would pass the cap." };
        }
        const widened = ask.scopes.some((sc) => !agent.scopes.includes(sc));
        if (widened) return { ok: false, error: "Delegation cannot widen scope." };
        if (ask.spendUqcb > s.balanceUqcb) return { ok: false, error: "Balance is short." };
        set({
          ask: null,
          balanceUqcb: s.balanceUqcb - ask.spendUqcb,
          nonce: s.nonce + 1,
          agents: s.agents.map((a) =>
            a.id === agent.id
              ? { ...a, uses: a.uses + 1, spentUqcb: a.spentUqcb + ask.spendUqcb }
              : a,
          ),
          rehearsed: mark(s.rehearsed, "approve"),
          activity: [
            {
              id: uid("act"),
              title: "Agent spend approved",
              detail: `${agent.name} · ${ask.resource} · ${ask.spendUqcb.toLocaleString("en-US")} uQCB`,
              at: nowStamp(),
            },
            ...s.activity,
          ],
        });
        return { ok: true };
      },
      denyAsk: () => {
        const s = get();
        if (!s.ask) return;
        set({
          ask: null,
          activity: [
            {
              id: uid("act"),
              title: "Agent spend denied",
              detail: "Human gate held. The agent key was not given a broader grant.",
              at: nowStamp(),
            },
            ...s.activity,
          ],
        });
      },
      revokeAgent: (id) => {
        const s = get();
        set({
          agents: s.agents.map((a) => (a.id === id ? { ...a, status: "revoked" as const } : a)),
          ask: s.ask?.agentId === id ? null : s.ask,
          activity: [
            {
              id: uid("act"),
              title: "Agent revoked",
              detail: `${id} · holder keys and other agents stay.`,
              at: nowStamp(),
            },
            ...s.activity,
          ],
        });
      },
      addAgent: (name, scopes, maxUses, spendCapUqcb) => {
        const clean = name.trim();
        if (clean.length < 2) return { ok: false, error: "Name the agent." };
        if (!scopes.length) return { ok: false, error: "Pick at least one scope." };
        if (maxUses < 1 || maxUses > 20) return { ok: false, error: "max_uses from 1 to 20." };
        const s = get();
        const agent: Agent = {
          id: uid("agent"),
          name: clean,
          scopes,
          maxUses,
          uses: 0,
          spendCapUqcb,
          spentUqcb: 0,
          humanGate: true,
          status: "active",
        };
        set({
          agents: [agent, ...s.agents],
          activity: [
            {
              id: uid("act"),
              title: "Agent delegated",
              detail: `${clean} · ${scopes.join(", ")} · depth 1 of 4`,
              at: nowStamp(),
            },
            ...s.activity,
          ],
        });
        return { ok: true };
      },
      sponsor: (kind, name, purpose, spendCapUqcb) => {
        const s = get();
        if (s.tier !== "verified") return { ok: false, error: "Only a verified human can sponsor." };
        const clean = name.trim();
        const why = purpose.trim();
        if (clean.length < 2) return { ok: false, error: "Name it." };
        if (why.length < 2) return { ok: false, error: "Say what it is for." };
        if (kind === "agent" && (spendCapUqcb == null || spendCapUqcb <= 0)) {
          return { ok: false, error: "Set a spending cap." };
        }
        const item: Sponsored =
          kind === "agent"
            ? {
                id: uid("sp"),
                kind: "agent",
                name: clean,
                purpose: why,
                spendCapUqcb: spendCapUqcb ?? 0,
                status: "active",
              }
            : { id: uid("sp"), kind: "contract", name: clean, purpose: why, status: "active" };
        set({
          sponsored: [item, ...s.sponsored],
          rehearsed: mark(s.rehearsed, "sponsor"),
          activity: [
            {
              id: uid("act"),
              title: kind === "agent" ? "Agent sponsored" : "Contract sponsored",
              detail: `${clean} · sponsor ${getAddress()}`,
              at: nowStamp(),
            },
            ...s.activity,
          ],
        });
        return { ok: true };
      },
      revokeSponsored: (id) => {
        const s = get();
        const item = s.sponsored.find((x) => x.id === id);
        if (!item || item.status === "revoked") return;
        set({
          sponsored: s.sponsored.map((x) => (x.id === id ? { ...x, status: "revoked" as const } : x)),
          activity: [
            {
              id: uid("act"),
              title: "Sponsorship revoked",
              detail: `${item.name} · the sponsor id stays on the record`,
              at: nowStamp(),
            },
            ...s.activity,
          ],
        });
      },
    }),
    {
      name: "qattice-wallet-v2",
      skipHydration: true,
      partialize: (s) => ({
        tab: s.tab,
        vendors: s.vendors,
        challenges: s.challenges,
        agents: s.agents,
        sponsored: s.sponsored,
        ask: s.ask,
        activity: s.activity,
        proof: s.proof,
        sessions: s.sessions,
        rehearsed: s.rehearsed,
        vote: s.vote,
        claimed: s.claimed,
      }),
      onRehydrateStorage: () => (state) => {
        state?.setHydrated();
      },
    },
  ),
);
