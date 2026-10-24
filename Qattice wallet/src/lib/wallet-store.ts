import { create } from "zustand";
import { persist } from "zustand/middleware";
import { getAddress } from "@/lib/keypair-store";
import {
  GAS_LIMIT,
  ATTESTATION_QUORUM,
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
  submitNodeTx,
  NODE_URL,
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
  send: (to: string, amountUqcb: number) => Promise<{ ok: true; digest: string } | { ok: false; error: string }>;
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
    balanceUqcb: 12_480_000,
    nonce: 7,
    tier: "provisional",
    attestations: 1,
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

export const useWallet = create<State>()(
  persist(
    (set, get) => ({
      ...base(),
      setHydrated: () => set({ hydrated: true }),
      setTab: (tab) => set({ tab }),
      setMoveMode: (moveMode) => set({ moveMode }),
      reset: () => set({ ...base(), hydrated: true }),
      syncFromNode: async () => {
        if (!NODE_URL) {
          set({ nodeConnected: false, nodeError: "Set VITE_NODE_URL to connect to a live node." });
          return;
        }
        const address = getAddress();
        const [identity, account] = await Promise.all([
          fetchNodeIdentity(address),
          fetchNodeAccount(address),
        ]);
        if (!identity && !account) {
          set({ nodeConnected: false, nodeError: `Cannot reach node at ${NODE_URL}` });
          return;
        }
        const update: Partial<State> = { nodeConnected: true, nodeError: null };
        if (account) {
          update.balanceUqcb = account.balances["uqcb"] ?? get().balanceUqcb;
          update.nonce = account.nonce;
        }
        if (identity) {
          update.attestations = identity.attestation_count;
          update.attested_by = identity.attested_by;
          if (identity.tier) update.tier = identity.tier as Tier;
        }
        set(update);
      },
      attest: async () => {
        const s = get();
        if (s.tier === "verified") return { ok: false, error: "Already verified." };
        const addr = getAddress();
        const chainId = (import.meta as { env?: Record<string, string> }).env?.VITE_CHAIN_ID ?? "qcb-devnet-fee-settle";
        // Register identity first if not yet on-chain
        const identity = await fetchNodeIdentity(addr);
        let attestNonce = s.nonce;
        if (!identity?.registered) {
          const regResult = await submitNodeTx({
            id: `reg-${addr}`,
            chain_id: chainId,
            sender: addr,
            nonce: s.nonce,
            gas_limit: GAS_LIMIT,
            body: "RegisterIdentity",
          });
          if (!regResult.ok) return { ok: false, error: `RegisterIdentity failed: ${regResult.error}` };
          // reg consumed nonce s.nonce, attest must use s.nonce + 1
          attestNonce = s.nonce + 1;
          // Wait briefly for the node to process before attesting
          await new Promise(r => setTimeout(r, 2000));
        }
        const body = { Attest: { claimant_id: addr } };
        const result = await submitNodeTx({
          id: `attest-${addr}-${attestNonce}`,
          chain_id: chainId,
          sender: addr,
          nonce: attestNonce,
          gas_limit: GAS_LIMIT,
          body,
        });
        if (!result.ok) {
          // fall back to local rehearsal if no node
          if (!NODE_URL) {
            const attestations = Math.min(ATTESTATION_QUORUM, s.attestations + 1);
            const tier: Tier = attestations >= ATTESTATION_QUORUM ? "verified" : "provisional";
            set({
              attestations,
              tier,
              rehearsed: tier === "verified" ? mark(s.rehearsed, "verified") : s.rehearsed,
              activity: [
                {
                  id: uid("act"),
                  title: tier === "verified" ? "Verified tier" : "Attestation recorded",
                  detail:
                    tier === "verified"
                      ? "Quorum of 3 reached in rehearsal."
                      : `${attestations} of ${ATTESTATION_QUORUM} attestors.`,
                  at: nowStamp(),
                },
                ...s.activity,
              ],
            });
            return { ok: true, tx_id: "rehearsal" };
          }
          return result;
        }
        set({
          nonce: s.nonce + 1,
          activity: [
            {
              id: uid("act"),
              title: "Attest tx submitted",
              detail: `tx ${result.tx_id}`,
              at: nowStamp(),
            },
            ...s.activity,
          ],
        });
        // refresh identity from node after a short delay
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
        if (dest === getAddress()) return { ok: false, error: "That is this wallet." };
        if (!Number.isInteger(amountUqcb) || amountUqcb <= 0) {
          return { ok: false, error: "Amount must be a positive whole number of uQCB." };
        }
        if (amountUqcb > s.balanceUqcb) return { ok: false, error: "Balance is short." };
        const body = { type: "Transfer", to: dest, amount: amountUqcb, denom: "uqcb" };
        const bodyJson = JSON.stringify(body);
        const digest = await sha256Hex(txPreimage(bodyJson));
        if (NODE_URL) {
          const result = await submitNodeTx({
            chain_id: (import.meta as { env?: Record<string, string> }).env?.VITE_CHAIN_ID ?? "qcb-devnet-fee-settle",
            sender: getAddress(),
            nonce: s.nonce,
            gas_limit: GAS_LIMIT,
            body,
          });
          if (!result.ok) return result;
          set({
            balanceUqcb: s.balanceUqcb - amountUqcb,
            nonce: s.nonce + 1,
            rehearsed: mark(s.rehearsed, "send"),
            activity: [
              {
                id: uid("act"),
                title: "Transfer submitted",
                detail: `${amountUqcb.toLocaleString("en-US")} uQCB → ${dest} · tx ${result.tx_id}`,
                at: nowStamp(),
              },
              ...s.activity,
            ],
          });
          setTimeout(() => void get().syncFromNode(), 1500);
          return { ok: true, digest: result.tx_id };
        }
        // rehearsal fallback (no node configured)
        set({
          balanceUqcb: s.balanceUqcb - amountUqcb,
          nonce: s.nonce + 1,
          rehearsed: mark(s.rehearsed, "send"),
          activity: [
            {
              id: uid("act"),
              title: "Transfer rehearsed",
              detail: `${amountUqcb.toLocaleString("en-US")} uQCB · nonce ${s.nonce} · gas ${GAS_LIMIT} · ${digest.slice(0, 16)}`,
              at: nowStamp(),
            },
            ...s.activity,
          ],
        });
        return { ok: true, digest };
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
        const digest = await sha256Hex(disPreimage(c, review.vendor.fingerprint));
        const proof: Proof = {
          challengeId: c.id,
          vendorId: review.vendor.id,
          fingerprint: review.vendor.fingerprint,
          digest,
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
              detail: `${review.vendor.name} · ${c.scopes.join(", ")} · QCB was not touched`,
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
      name: "qattice-rehearsal-v1",
      skipHydration: true,
      partialize: (s) => ({
        tab: s.tab,
        balanceUqcb: s.balanceUqcb,
        nonce: s.nonce,
        tier: s.tier,
        attestations: s.attestations,
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
