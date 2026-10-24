import { i as __toESM } from "../_runtime.mjs";
import { q as require_react, x as require_jsx_runtime } from "../_libs/@tanstack/react-router+[...].mjs";
import { a as Bot, i as Fingerprint, n as ListChecks, o as ArrowLeftRight, r as Hexagon } from "../_libs/lucide-react.mjs";
import { n as toast, t as Toaster } from "../_libs/sonner.mjs";
import { n as create, t as persist } from "../_libs/zustand.mjs";
import { t as require_lib } from "../_libs/qrcode.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/routes-BNCaErlU.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
var import_lib = /* @__PURE__ */ __toESM(require_lib());
var UQCB = 1e6;
var CHAIN_ID = "qcb-testnet-4node";
var ADDRESS = "qcb1pq1k4rm7w4llet9h0lder2charm";
var TX_DOMAIN = "chain-forge/pq-tx/v1";
var DIS_DOMAIN = "DIS-KS-V1";
var GAS_LIMIT = 8e4;
var SESSION_MS = 9e5;
function formatQcb(uqcb) {
	const sign = uqcb < 0 ? "-" : "";
	const v = Math.abs(Math.trunc(uqcb));
	const whole = Math.floor(v / UQCB);
	const frac = String(v % UQCB).padStart(6, "0");
	return `${sign}${whole.toLocaleString("en-US")}.${frac}`;
}
function formatUqcb(uqcb) {
	return `${Math.trunc(uqcb).toLocaleString("en-US")} uQCB`;
}
function shortAddress(address) {
	if (address.length < 18) return address;
	return `${address.slice(0, 10)}…${address.slice(-4)}`;
}
function fingerprint(seed) {
	let h = 2166136261;
	for (const c of seed) h = Math.imul(h ^ c.charCodeAt(0), 16777619);
	return (h >>> 0).toString(16).padStart(8, "0");
}
function uid(prefix) {
	return `${prefix}-${Math.random().toString(36).slice(2, 8)}`;
}
async function sha256Hex(message) {
	const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(message));
	return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function txPreimage(bodyJson) {
	return `${TX_DOMAIN}\n${CHAIN_ID}\n${bodyJson}`;
}
function disPreimage(c, vendorFingerprint) {
	return [
		DIS_DOMAIN,
		c.rpId,
		c.origin,
		c.resource,
		c.action,
		c.scopes.join(","),
		c.nonce,
		String(c.exp),
		vendorFingerprint
	].join("\n");
}
function reviewChallenge(c, vendors, now) {
	const reasons = [];
	const vendor = vendors.find((v) => v.id === c.rpId && v.status === "active");
	if (now > c.exp) reasons.push("Challenge expired. DIS challenges are single-use and live about 60 seconds.");
	if (!vendor) reasons.push("No active key for this relying party. Provision that vendor before signing.");
	else if (vendor.origin !== c.origin) reasons.push("Audience does not match the enrolled origin. Cross-vendor reuse is rejected.");
	else {
		const outside = c.scopes.filter((s) => !vendor.grants.includes(s));
		if (outside.length) reasons.push(`Scope is not in this vendor’s grant: ${outside.join(", ")}.`);
	}
	if (c.kind === "delegated" && (c.spendUqcb ?? 0) > 0) reasons.push("Delegated spend needs the human-approval gate on the Agents desk, not a blind Stone signature.");
	return {
		ok: reasons.length === 0,
		reasons,
		vendor
	};
}
function parseChallenge(raw, now) {
	let data;
	try {
		data = JSON.parse(raw);
	} catch {
		return { error: "That is not JSON. Paste the vendor challenge object." };
	}
	if (!data || typeof data !== "object") return { error: "Challenge must be a JSON object." };
	const o = data;
	const rpId = str(o.rp_id ?? o.rpId ?? o.vendor_id ?? o.vendorId);
	const origin = str(o.origin ?? o.rp_origin ?? o.audience);
	const resource = str(o.resource ?? o.resource_id ?? o.resourceId);
	const action = str(o.action) || "read";
	const nonce = str(o.nonce ?? o.challenge_id ?? o.id) || uid("ch");
	if (!rpId || !origin || !resource) return { error: "Need rp_id (or vendor_id), origin, and resource." };
	const scopesRaw = o.scopes ?? o.scope;
	const scopes = Array.isArray(scopesRaw) ? scopesRaw.map(String) : typeof scopesRaw === "string" && scopesRaw ? scopesRaw.split(/[,\s]+/).filter(Boolean) : [action];
	let exp = now + 6e4;
	const expRaw = o.exp ?? o.expires ?? o.expiry;
	if (typeof expRaw === "number") exp = expRaw < 1e10 ? expRaw * 1e3 : expRaw;
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
		agent: str(o.agent) || void 0,
		spendUqcb: typeof o.spend_uqcb === "number" ? o.spend_uqcb : void 0
	};
}
function str(v) {
	return typeof v === "string" ? v.trim() : "";
}
function freshChallenge(now) {
	return {
		id: uid("ch"),
		rpId: "docs",
		origin: "https://docs.qattice.test",
		resource: "document:001",
		action: "read",
		scopes: ["document:read"],
		nonce: uid("n"),
		exp: now + 6e4,
		kind: "holder"
	};
}
var SPEC = [
	{
		id: "provision",
		group: "phone",
		title: "Provision a vendor key",
		detail: "The test APK already takes a vendor id and origin and generates an ML-DSA-65 key through the JNI bridge. Keep that. Do not turn it into one global login key.",
		surface: "stone"
	},
	{
		id: "scan",
		group: "phone",
		title: "Scan or paste a challenge",
		detail: "QR scan and a paste field exist. The sophisticated app must parse the challenge into bindings before anything is signed — the phone today drops raw JSON into a box.",
		surface: "stone"
	},
	{
		id: "local-sign",
		group: "phone",
		title: "Sign on the device",
		detail: "Private keys stay in Android Keystore (AES-256-GCM). The node and the vendor receive a proof, never the key. This rehearsal does not replace that custody.",
		surface: "stone"
	},
	{
		id: "server-auth",
		group: "phone",
		title: "Vendor server round-trip",
		detail: "enroll → issue challenge → verify, via VendorServerClient. Production still needs authenticated enrollment, not enroll_test_key.",
		surface: "stone"
	},
	{
		id: "chain-account",
		group: "next",
		title: "Separate chain account",
		detail: "chain-forge-wallet already derives a qcb1pq address from the ML-DSA-65 public key and signs transfers. The Android UI has no balance, nonce, or send. The chain key and the per-vendor DIS keys are different keys.",
		surface: "home",
		rehearsal: "send"
	},
	{
		id: "envelope",
		group: "next",
		title: "Signed transaction envelope",
		detail: "Prehash is SHA-256 of chain-forge/pq-tx/v1, the chain id, and the tx body. Submit only SignedTxEnvelope — id, sender, nonce, body, gas_limit, signature tagged mldsa65 — to POST /api/tx.",
		surface: "move",
		rehearsal: "send"
	},
	{
		id: "nonce",
		group: "next",
		title: "Nonce, chain id, denom",
		detail: "Nonce must equal the account nonce. Replay and gaps over 100 are rejected. Chain id is bound into the signature so a testnet signature cannot ride onto another chain. Denom is uQCB. 1 QCB = 1,000,000 uQCB. Older samples still say uqrc; do not ship that name.",
		surface: "move",
		rehearsal: "send"
	},
	{
		id: "consent",
		group: "next",
		title: "Show bindings before sign",
		detail: "Audience, resource, action, scope, nonce, and expiry. Refuse expired challenges, wrong origin, and scopes outside the vendor grant. A 60-second single-use challenge is the doorway, not a session token.",
		surface: "stone",
		rehearsal: "sign"
	},
	{
		id: "session",
		group: "next",
		title: "Scoped session, not a login token",
		detail: "A good signature consumes the challenge and opens one vendor grant. That grant cannot be replayed at another vendor, and it cannot move QCB. Rotating that vendor’s key ends only that session.",
		surface: "stone",
		rehearsal: "session"
	},
	{
		id: "unlink",
		group: "next",
		title: "Unlinkable vendor keys",
		detail: "DIS-PRIV-001: each relying party gets its own public key. Rotating or revoking one vendor must not move the others (DIS-KS-002). The UI should show the fingerprints side by side so that is obvious.",
		surface: "stone",
		rehearsal: "rotate"
	},
	{
		id: "tier",
		group: "next",
		title: "Identity tier is not a login",
		detail: "A successful DIS sign-in does not prove personhood. Provisional becomes Verified only after an attestation quorum of 3. Verified unlocks personhood-weighted participation, activity rewards, governance, and charmed-agent sponsorship. Liveness is periodic participation, not a badge you keep forever.",
		surface: "home",
		rehearsal: "verified"
	},
	{
		id: "participate",
		group: "next",
		title: "Verified participation",
		detail: "Activity rewards and governance stay closed until the attestation quorum. One verified human, one vote. The weight is personhood, not the QCB balance. A vendor session does not unlock either.",
		surface: "home",
		rehearsal: "participate"
	},
	{
		id: "sponsor",
		group: "next",
		title: "SponsorID on agents and contracts",
		detail: "A verified human can sponsor a charmed agent or a contract. The sponsor id is the qcb1pq account, so the chain can hold that human accountable. A provisional identity and a DIS login cannot sponsor. This rehearsal records the intent. It does not deploy to the devnet.",
		surface: "agents",
		rehearsal: "sponsor"
	},
	{
		id: "agents",
		group: "next",
		title: "Delegated agents",
		detail: "Depth at most 4. Scopes may only narrow. max_uses is counted. High-risk and spend actions stop on a human-approval gate. Spending limits are part of the design; durable server enforcement is still a return gate.",
		surface: "agents",
		rehearsal: "approve"
	},
	{
		id: "reject",
		group: "next",
		title: "Refuse a bad challenge in the UI",
		detail: "Forged, expired, cross-audience, and scope-injected challenges are already rejected by the protocol tests. The wallet should explain the refusal before the user taps Sign, instead of returning a raw error string.",
		surface: "stone",
		rehearsal: "reject"
	},
	{
		id: "hsm",
		group: "gate",
		title: "Keystore is not an audit",
		detail: "AES-256-GCM in Android Keystore is the right direction. Production still replaces DemoWallet with an HSM or OS-backed ceremony, and the transcript format still wants an independent review."
	},
	{
		id: "recovery",
		group: "gate",
		title: "No recovery design yet",
		detail: "DIS-PQ-001 says return to wallet key recovery before production. Do not add a seed phrase that can resurrect a compromised key. Recovery has to issue a new key and preserve vendor continuity."
	},
	{
		id: "tls",
		group: "gate",
		title: "Hybrid TLS and real enrollment",
		detail: "Vendor origins still need post-quantum hybrid TLS. Enrollment must be RP-authenticated. Conformance vectors still need a non-Rust client. This rehearsal records intent and digests only — it does not emit ML-DSA signatures."
	}
];
var REWARD_UQCB = 5e4;
var PROPOSAL = {
	id: "personhood-cap",
	title: "Cap one human’s validator weight",
	detail: "A verified human’s vote is capped. Stake alone cannot raise that weight."
};
function seedVendors() {
	return [
		{
			id: "docs",
			name: "Docs",
			origin: "https://docs.qattice.test",
			grants: ["document:read"],
			fingerprint: fingerprint("docs-seed"),
			status: "active"
		},
		{
			id: "merchant",
			name: "Merchant",
			origin: "https://pay.qattice.test",
			grants: ["payment:request"],
			fingerprint: fingerprint("merchant-seed"),
			status: "active"
		},
		{
			id: "agents",
			name: "Agent host",
			origin: "https://agents.qattice.test",
			grants: ["agent:spawn", "agent:spend"],
			fingerprint: fingerprint("agents-seed"),
			status: "active"
		}
	];
}
function seedAgents() {
	return [{
		id: "courier",
		name: "Courier",
		scopes: ["payment:request"],
		maxUses: 5,
		uses: 1,
		spendCapUqcb: 1e6,
		spentUqcb: 1e5,
		humanGate: true,
		status: "active"
	}];
}
function nowStamp() {
	return Date.now();
}
function base() {
	const now = nowStamp();
	return {
		hydrated: false,
		tab: "home",
		moveMode: "send",
		balanceUqcb: 1248e4,
		nonce: 7,
		tier: "provisional",
		attestations: 1,
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
			spendUqcb: 25e4
		},
		activity: [{
			id: "act-seed",
			title: "Vendor key provisioned",
			detail: "docs · fingerprint from the phone test wallet’s shape",
			at: now - 936e5
		}],
		proof: null,
		sessions: [],
		rehearsed: [],
		vote: null,
		claimed: false
	};
}
function mark(list, key) {
	return list.includes(key) ? list : [...list, key];
}
var useWallet = create()(persist((set, get) => ({
	...base(),
	setHydrated: () => set({ hydrated: true }),
	setTab: (tab) => set({ tab }),
	setMoveMode: (moveMode) => set({ moveMode }),
	reset: () => set({
		...base(),
		hydrated: true
	}),
	attest: () => {
		const s = get();
		if (s.tier === "verified") return;
		const attestations = Math.min(3, s.attestations + 1);
		const tier = attestations >= 3 ? "verified" : "provisional";
		set({
			attestations,
			tier,
			rehearsed: tier === "verified" ? mark(s.rehearsed, "verified") : s.rehearsed,
			activity: [{
				id: uid("act"),
				title: tier === "verified" ? "Verified tier" : "Attestation recorded",
				detail: tier === "verified" ? "Quorum of 3 reached in this rehearsal. Personhood is still a separate credential from DIS login." : `${attestations} of 3 independent attestors.`,
				at: nowStamp()
			}, ...s.activity]
		});
	},
	claim: () => {
		const s = get();
		if (s.tier !== "verified") return {
			ok: false,
			error: "Provisional identities cannot claim."
		};
		if (s.claimed) return {
			ok: false,
			error: "Already claimed in this rehearsal."
		};
		set({
			claimed: true,
			balanceUqcb: s.balanceUqcb + REWARD_UQCB,
			rehearsed: mark(s.rehearsed, "participate"),
			activity: [{
				id: uid("act"),
				title: "Activity reward claimed",
				detail: `${REWARD_UQCB.toLocaleString("en-US")} uQCB · verified participation, not a vendor login`,
				at: nowStamp()
			}, ...s.activity]
		});
		return { ok: true };
	},
	castVote: (choice) => {
		const s = get();
		if (s.tier !== "verified") return {
			ok: false,
			error: "Provisional identities cannot vote."
		};
		if (s.vote) return {
			ok: false,
			error: "This proposal already has your vote."
		};
		set({
			vote: choice,
			rehearsed: mark(s.rehearsed, "participate"),
			activity: [{
				id: uid("act"),
				title: "Governance vote cast",
				detail: `${choice} · one human, one vote · not weighted by the QCB balance`,
				at: nowStamp()
			}, ...s.activity]
		});
		return { ok: true };
	},
	send: async (to, amountUqcb) => {
		const s = get();
		const dest = to.trim();
		if (!dest.startsWith("qcb1")) return {
			ok: false,
			error: "Recipient must be a qcb1 address."
		};
		if (dest === "qcb1pq1k4rm7w4llet9h0lder2charm") return {
			ok: false,
			error: "That is this wallet."
		};
		if (!Number.isInteger(amountUqcb) || amountUqcb <= 0) return {
			ok: false,
			error: "Amount must be a positive whole number of uQCB."
		};
		if (amountUqcb > s.balanceUqcb) return {
			ok: false,
			error: "Balance is short."
		};
		const digest = await sha256Hex(txPreimage(JSON.stringify({
			type: "Transfer",
			to: dest,
			amount: amountUqcb,
			denom: "uqcb"
		})));
		set({
			balanceUqcb: s.balanceUqcb - amountUqcb,
			nonce: s.nonce + 1,
			rehearsed: mark(s.rehearsed, "send"),
			activity: [{
				id: uid("act"),
				title: "Transfer rehearsed",
				detail: `${amountUqcb.toLocaleString("en-US")} uQCB · nonce ${s.nonce} · gas ${GAS_LIMIT} · ${digest.slice(0, 16)}`,
				at: nowStamp()
			}, ...s.activity]
		});
		return {
			ok: true,
			digest
		};
	},
	pushChallenge: (c) => set({ challenges: [c, ...get().challenges.filter((x) => x.id !== c.id)] }),
	loadFresh: () => {
		set({ challenges: [freshChallenge(nowStamp()), ...get().challenges] });
	},
	loadBad: (kind) => {
		const now = nowStamp();
		const c = freshChallenge(now);
		if (kind === "expired") c.exp = now - 5e3;
		if (kind === "audience") c.origin = "https://other.vendor.test";
		if (kind === "scope") c.scopes = ["document:read", "admin:write"];
		c.id = uid("bad");
		set({ challenges: [c, ...get().challenges] });
	},
	sign: async (id) => {
		const s = get();
		const c = s.challenges.find((x) => x.id === id);
		if (!c) return {
			ok: false,
			error: "Challenge is gone."
		};
		const review = reviewChallenge(c, s.vendors, nowStamp());
		if (!review.ok || !review.vendor) return {
			ok: false,
			error: review.reasons[0] ?? "Refused."
		};
		const digest = await sha256Hex(disPreimage(c, review.vendor.fingerprint));
		const proof = {
			challengeId: c.id,
			vendorId: review.vendor.id,
			fingerprint: review.vendor.fingerprint,
			digest,
			at: nowStamp(),
			resource: c.resource,
			action: c.action
		};
		const opened = nowStamp();
		const session = {
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
			exp: opened + SESSION_MS
		};
		set({
			proof,
			sessions: [session, ...s.sessions.filter((x) => x.vendorId !== session.vendorId)],
			challenges: s.challenges.filter((x) => x.id !== id),
			rehearsed: mark(s.rehearsed, "sign"),
			activity: [{
				id: uid("act"),
				title: "Session opened",
				detail: `${review.vendor.name} · ${c.scopes.join(", ")} · QCB was not touched`,
				at: opened
			}, ...s.activity]
		});
		return { ok: true };
	},
	useAccess: (id, scope) => {
		const s = get();
		const session = s.sessions.find((x) => x.id === id);
		if (!session) return {
			ok: false,
			error: "Session is gone."
		};
		if (nowStamp() > session.exp) return {
			ok: false,
			error: "Grant ended. Ask the vendor for a new challenge."
		};
		if (!session.scopes.includes(scope)) return {
			ok: false,
			error: `This ${session.vendorName} session cannot use ${scope}.`
		};
		set({
			rehearsed: mark(s.rehearsed, "session"),
			activity: [{
				id: uid("act"),
				title: "Vendor access",
				detail: `${session.vendorName} · ${session.resource} · ${scope}`,
				at: nowStamp()
			}, ...s.activity]
		});
		return {
			ok: true,
			detail: `${session.vendorName} allowed ${scope} on ${session.resource}. The chain balance did not move.`
		};
	},
	endSession: (id) => {
		const s = get();
		const session = s.sessions.find((x) => x.id === id);
		if (!session) return;
		set({
			sessions: s.sessions.filter((x) => x.id !== id),
			activity: [{
				id: uid("act"),
				title: "Session ended",
				detail: `${session.vendorName} · other vendors were not signed out`,
				at: nowStamp()
			}, ...s.activity]
		});
	},
	reject: (id, reason) => {
		const s = get();
		const c = s.challenges.find((x) => x.id === id);
		if (!c) return;
		set({
			challenges: s.challenges.filter((x) => x.id !== id),
			rehearsed: mark(s.rehearsed, "reject"),
			activity: [{
				id: uid("act"),
				title: "Challenge refused",
				detail: `${c.rpId} · ${reason}`,
				at: nowStamp()
			}, ...s.activity]
		});
	},
	provision: (id, origin, grants) => {
		const clean = id.trim().toLowerCase();
		if (!/^[a-z][a-z0-9-]{1,24}$/.test(clean)) return {
			ok: false,
			error: "Vendor id: letters, numbers, hyphen. 2–25 characters."
		};
		if (!origin.startsWith("https://")) return {
			ok: false,
			error: "Origin must be https."
		};
		if (!grants.length) return {
			ok: false,
			error: "Add at least one scope grant."
		};
		const s = get();
		if (s.vendors.some((v) => v.id === clean)) return {
			ok: false,
			error: "That vendor already has a key."
		};
		const vendor = {
			id: clean,
			name: clean,
			origin: origin.trim(),
			grants,
			fingerprint: fingerprint(`${clean}-${nowStamp()}`),
			status: "active"
		};
		set({
			vendors: [...s.vendors, vendor],
			activity: [{
				id: uid("act"),
				title: "Vendor provisioned",
				detail: `${clean} · ${vendor.fingerprint} · not shared with other vendors`,
				at: nowStamp()
			}, ...s.activity]
		});
		return { ok: true };
	},
	rotate: (id) => {
		const s = get();
		const next = fingerprint(`${id}-rot-${nowStamp()}`);
		set({
			vendors: s.vendors.map((v) => v.id === id ? {
				...v,
				fingerprint: next,
				status: "active"
			} : v),
			sessions: s.sessions.filter((ses) => ses.vendorId !== id),
			rehearsed: mark(s.rehearsed, "rotate"),
			activity: [{
				id: uid("act"),
				title: "Vendor key rotated",
				detail: `${id} · new fingerprint ${next}. That vendor’s session ended. Others were not touched.`,
				at: nowStamp()
			}, ...s.activity]
		});
	},
	approveAsk: () => {
		const s = get();
		const ask = s.ask;
		if (!ask) return {
			ok: false,
			error: "Nothing is waiting."
		};
		const agent = s.agents.find((a) => a.id === ask.agentId && a.status === "active");
		if (!agent) return {
			ok: false,
			error: "Agent is not active."
		};
		if (agent.uses >= agent.maxUses) return {
			ok: false,
			error: "max_uses is exhausted."
		};
		if (agent.spentUqcb + ask.spendUqcb > agent.spendCapUqcb) return {
			ok: false,
			error: "Spend would pass the cap."
		};
		if (ask.scopes.some((sc) => !agent.scopes.includes(sc))) return {
			ok: false,
			error: "Delegation cannot widen scope."
		};
		if (ask.spendUqcb > s.balanceUqcb) return {
			ok: false,
			error: "Balance is short."
		};
		set({
			ask: null,
			balanceUqcb: s.balanceUqcb - ask.spendUqcb,
			nonce: s.nonce + 1,
			agents: s.agents.map((a) => a.id === agent.id ? {
				...a,
				uses: a.uses + 1,
				spentUqcb: a.spentUqcb + ask.spendUqcb
			} : a),
			rehearsed: mark(s.rehearsed, "approve"),
			activity: [{
				id: uid("act"),
				title: "Agent spend approved",
				detail: `${agent.name} · ${ask.resource} · ${ask.spendUqcb.toLocaleString("en-US")} uQCB`,
				at: nowStamp()
			}, ...s.activity]
		});
		return { ok: true };
	},
	denyAsk: () => {
		const s = get();
		if (!s.ask) return;
		set({
			ask: null,
			activity: [{
				id: uid("act"),
				title: "Agent spend denied",
				detail: "Human gate held. The agent key was not given a broader grant.",
				at: nowStamp()
			}, ...s.activity]
		});
	},
	revokeAgent: (id) => {
		const s = get();
		set({
			agents: s.agents.map((a) => a.id === id ? {
				...a,
				status: "revoked"
			} : a),
			ask: s.ask?.agentId === id ? null : s.ask,
			activity: [{
				id: uid("act"),
				title: "Agent revoked",
				detail: `${id} · holder keys and other agents stay.`,
				at: nowStamp()
			}, ...s.activity]
		});
	},
	addAgent: (name, scopes, maxUses, spendCapUqcb) => {
		const clean = name.trim();
		if (clean.length < 2) return {
			ok: false,
			error: "Name the agent."
		};
		if (!scopes.length) return {
			ok: false,
			error: "Pick at least one scope."
		};
		if (maxUses < 1 || maxUses > 20) return {
			ok: false,
			error: "max_uses from 1 to 20."
		};
		const s = get();
		set({
			agents: [{
				id: uid("agent"),
				name: clean,
				scopes,
				maxUses,
				uses: 0,
				spendCapUqcb,
				spentUqcb: 0,
				humanGate: true,
				status: "active"
			}, ...s.agents],
			activity: [{
				id: uid("act"),
				title: "Agent delegated",
				detail: `${clean} · ${scopes.join(", ")} · depth 1 of 4`,
				at: nowStamp()
			}, ...s.activity]
		});
		return { ok: true };
	},
	sponsor: (kind, name, purpose, spendCapUqcb) => {
		const s = get();
		if (s.tier !== "verified") return {
			ok: false,
			error: "Only a verified human can sponsor."
		};
		const clean = name.trim();
		const why = purpose.trim();
		if (clean.length < 2) return {
			ok: false,
			error: "Name it."
		};
		if (why.length < 2) return {
			ok: false,
			error: "Say what it is for."
		};
		if (kind === "agent" && (spendCapUqcb == null || spendCapUqcb <= 0)) return {
			ok: false,
			error: "Set a spending cap."
		};
		set({
			sponsored: [kind === "agent" ? {
				id: uid("sp"),
				kind: "agent",
				name: clean,
				purpose: why,
				spendCapUqcb: spendCapUqcb ?? 0,
				status: "active"
			} : {
				id: uid("sp"),
				kind: "contract",
				name: clean,
				purpose: why,
				status: "active"
			}, ...s.sponsored],
			rehearsed: mark(s.rehearsed, "sponsor"),
			activity: [{
				id: uid("act"),
				title: kind === "agent" ? "Agent sponsored" : "Contract sponsored",
				detail: `${clean} · sponsor ${ADDRESS}`,
				at: nowStamp()
			}, ...s.activity]
		});
		return { ok: true };
	},
	revokeSponsored: (id) => {
		const s = get();
		const item = s.sponsored.find((x) => x.id === id);
		if (!item || item.status === "revoked") return;
		set({
			sponsored: s.sponsored.map((x) => x.id === id ? {
				...x,
				status: "revoked"
			} : x),
			activity: [{
				id: uid("act"),
				title: "Sponsorship revoked",
				detail: `${item.name} · the sponsor id stays on the record`,
				at: nowStamp()
			}, ...s.activity]
		});
	}
}), {
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
		claimed: s.claimed
	}),
	onRehydrateStorage: () => (state) => {
		state?.setHydrated();
	}
}));
function Mark({ className }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("svg", {
		viewBox: "0 0 32 32",
		className,
		"aria-hidden": true,
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("path", {
			d: "M4 16h8M20 16h8M16 4v8M16 20v8M9 9l5 5M18 18l5 5M23 9l-5 5M14 18l-5 5",
			fill: "none",
			stroke: "currentColor",
			strokeWidth: "1.4"
		}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("circle", {
			cx: "16",
			cy: "16",
			r: "2.1",
			fill: "currentColor"
		})]
	});
}
function SectionLabel({ children }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
		className: "text-xs font-medium tracking-widest text-mist uppercase",
		children
	});
}
function Card({ children, className = "" }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("section", {
		className: `rounded-2xl border border-line bg-panel p-4 ${className}`,
		children
	});
}
function Field({ label, children }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("label", {
		className: "block",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
			className: "mb-1.5 block text-xs font-medium tracking-wide text-mist uppercase",
			children: label
		}), children]
	});
}
var inputClass = "h-12 w-full rounded-xl border border-line bg-raised px-3 text-base text-parchment outline-none placeholder:text-mist/70 focus:border-brass disabled:opacity-40";
function PrimaryButton({ children, onClick, disabled, type = "button" }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
		type,
		onClick,
		disabled,
		className: "h-12 w-full rounded-xl bg-brass px-4 text-base font-medium text-ink transition-opacity disabled:opacity-40",
		children
	});
}
function GhostButton({ children, onClick, disabled }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
		type: "button",
		onClick,
		disabled,
		className: "h-12 w-full rounded-xl border border-line bg-raised px-4 text-sm font-medium text-parchment disabled:opacity-40",
		children
	});
}
async function copyText(value, label) {
	try {
		await navigator.clipboard.writeText(value);
		toast(label);
	} catch {
		toast("Copy is blocked in this browser");
	}
}
function Row({ k, v }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "flex items-start justify-between gap-4 border-b border-line/80 py-2 last:border-0",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("dt", {
			className: "text-sm text-mist",
			children: k
		}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("dd", {
			className: "max-w-[16rem] text-right font-mono text-sm break-all text-parchment",
			children: v
		})]
	});
}
function useNow(active) {
	const [now, setNow] = (0, import_react.useState)(() => Date.now());
	(0, import_react.useEffect)(() => {
		if (!active) return;
		const id = window.setInterval(() => setNow(Date.now()), 1e3);
		return () => window.clearInterval(id);
	}, [active]);
	return now;
}
function ago(at) {
	const s = Math.max(0, Math.round((Date.now() - at) / 1e3));
	if (s < 60) return "just now";
	const m = Math.round(s / 60);
	if (m < 60) return `${m}m ago`;
	const h = Math.round(m / 60);
	if (h < 48) return `${h}h ago`;
	return `${Math.round(h / 24)}d ago`;
}
function qcbToUqcb(input) {
	const t = input.trim();
	if (!/^\d+(\.\d{0,6})?$/.test(t)) return null;
	const [w, f = ""] = t.split(".");
	const frac = (f + "000000").slice(0, 6);
	const n = Number(w) * UQCB + Number(frac);
	if (!Number.isSafeInteger(n) || n <= 0) return null;
	return n;
}
function HomeScreen({ go }) {
	const balance = useWallet((s) => s.balanceUqcb);
	const tier = useWallet((s) => s.tier);
	const attestations = useWallet((s) => s.attestations);
	const attest = useWallet((s) => s.attest);
	const claim = useWallet((s) => s.claim);
	const castVote = useWallet((s) => s.castVote);
	const vote = useWallet((s) => s.vote);
	const claimed = useWallet((s) => s.claimed);
	const activity = useWallet((s) => s.activity);
	const vendors = useWallet((s) => s.vendors);
	const setMoveMode = useWallet((s) => s.setMoveMode);
	const openSessions = useWallet((s) => s.sessions).filter((ses) => ses.exp > Date.now());
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "space-y-6",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("header", {
				className: "flex items-start justify-between gap-4",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "flex items-center gap-2 text-brass",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Mark, { className: "h-7 w-7" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("h1", {
						className: "font-display text-3xl font-medium tracking-tight text-parchment",
						children: "Qattice"
					})]
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-1 text-sm text-mist",
					children: "Rehearsal wallet · keys stay on the phone"
				})] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "rounded-full border border-line px-3 py-1 text-xs text-mist",
					children: CHAIN_ID.replace("qcb-", "")
				})]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "font-display text-4xl font-medium tracking-tight text-parchment",
				children: formatQcb(balance)
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
				className: "mt-1 text-sm text-mist",
				children: ["QCB · ", formatUqcb(balance)]
			})] }),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
				type: "button",
				onClick: () => void copyText(ADDRESS, "Address copied"),
				className: "flex w-full items-center justify-between rounded-2xl border border-line bg-panel px-4 py-3 text-left",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
					className: "block text-xs text-mist",
					children: "Chain account"
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
					className: "font-mono text-sm text-parchment",
					children: shortAddress(ADDRESS)
				})] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
					className: "text-sm text-brass",
					children: "Copy"
				})]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex items-start justify-between gap-3",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(SectionLabel, { children: "Identity tier" }),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-1 font-display text-2xl text-parchment capitalize",
						children: tier
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
						className: "mt-1 text-sm text-mist",
						children: [
							attestations,
							" of ",
							3,
							" attestations. A DIS login is not personhood."
						]
					})
				] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
					className: "mt-1 h-2.5 w-2.5 rounded-full bg-brass",
					"aria-hidden": true
				})]
			}), tier === "provisional" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: "mt-4",
				children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(PrimaryButton, {
					onClick: attest,
					children: "Record attestation"
				})
			}) : /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "mt-4",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "text-sm text-mist",
					children: "Quorum met. Sponsorship uses this identity, not a Docs session."
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
					className: "mt-3",
					children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(GhostButton, {
						onClick: () => go("agents"),
						children: "Open sponsor desk"
					})
				})]
			})] }),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, { children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(SectionLabel, { children: "Participation" }),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-2 text-base text-parchment",
					children: PROPOSAL.title
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-1 text-sm text-mist",
					children: PROPOSAL.detail
				}),
				vote ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
					className: "mt-3 text-sm text-parchment",
					children: [
						"You voted ",
						vote,
						". It counts once."
					]
				}) : /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "mt-4 grid grid-cols-2 gap-2",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(GhostButton, {
						disabled: tier !== "verified",
						onClick: () => {
							const result = castVote("yes");
							if (!result.ok) toast(result.error);
						},
						children: "Vote yes"
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(GhostButton, {
						disabled: tier !== "verified",
						onClick: () => {
							const result = castVote("no");
							if (!result.ok) toast(result.error);
						},
						children: "Vote no"
					})]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
					className: "mt-3",
					children: claimed ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
						className: "text-sm text-parchment",
						children: [
							"Reward claimed · ",
							formatQcb(REWARD_UQCB),
							" QCB"
						]
					}) : /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(PrimaryButton, {
						disabled: tier !== "verified",
						onClick: () => {
							const result = claim();
							if (!result.ok) toast(result.error);
							else toast("Reward claimed");
						},
						children: [
							"Claim ",
							formatQcb(REWARD_UQCB),
							" QCB"
						]
					})
				}),
				tier !== "verified" ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
					className: "mt-3 text-sm text-mist",
					children: [
						"Locked until ",
						3,
						" attestations. Signing in to Docs will not open this."
					]
				}) : null
			] }),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "grid grid-cols-3 gap-2",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(GhostButton, {
						onClick: () => {
							setMoveMode("send");
							go("move");
						},
						children: "Send"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(GhostButton, {
						onClick: () => {
							setMoveMode("receive");
							go("move");
						},
						children: "Receive"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(GhostButton, {
						onClick: () => go("stone"),
						children: "Sign"
					})
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "grid gap-3",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
						className: "text-sm text-mist",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
							className: "text-parchment",
							children: "Chain key. "
						}), "One qcb1pq address signs QCB transfers. Nonce lives on the account."]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
						className: "text-sm text-mist",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
							className: "text-parchment",
							children: [vendors.length, " vendor keys. "]
						}), "Each relying party has its own ML-DSA fingerprint. They are not this address."]
					}),
					openSessions.length > 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
						className: "text-sm text-mist",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
								className: "text-parchment",
								children: [
									openSessions.length,
									" vendor session",
									openSessions.length === 1 ? "" : "s",
									". "
								]
							}),
							openSessions.map((ses) => ses.vendorName).join(", "),
							" can use their grant. They cannot spend this balance."
						]
					}) : null
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(SectionLabel, { children: "Recent" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
				className: "mt-3 divide-y divide-line",
				children: activity.slice(0, 5).map((item) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
					className: "py-3",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "text-sm text-parchment",
							children: item.title
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "text-sm text-mist",
							children: item.detail
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "text-xs text-mist",
							children: ago(item.at)
						})
					]
				}, item.id))
			})] })
		]
	});
}
function StoneScreen() {
	const now = useNow(true);
	const challenges = useWallet((s) => s.challenges);
	const vendors = useWallet((s) => s.vendors);
	const proof = useWallet((s) => s.proof);
	const sessions = useWallet((s) => s.sessions);
	const sign = useWallet((s) => s.sign);
	const reject = useWallet((s) => s.reject);
	const loadFresh = useWallet((s) => s.loadFresh);
	const loadBad = useWallet((s) => s.loadBad);
	const push = useWallet((s) => s.pushChallenge);
	const provision = useWallet((s) => s.provision);
	const rotate = useWallet((s) => s.rotate);
	const [raw, setRaw] = (0, import_react.useState)("");
	const [pasteError, setPasteError] = (0, import_react.useState)("");
	const [vendorId, setVendorId] = (0, import_react.useState)("");
	const [origin, setOrigin] = (0, import_react.useState)("https://");
	const [grants, setGrants] = (0, import_react.useState)("document:read");
	const [formError, setFormError] = (0, import_react.useState)("");
	const [open, setOpen] = (0, import_react.useState)(false);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "space-y-6",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(SectionLabel, { children: "Digital Identity Stone" }),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
					className: "mt-1 font-display text-3xl text-parchment",
					children: "Sign what you can read"
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-2 text-sm text-mist",
					children: "The phone test wallet signs whatever JSON is in the box. A good signature here opens one vendor grant. It is not a chain login, and it does not move QCB."
				})
			] }),
			sessions.length > 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
				className: "space-y-3",
				children: sessions.map((ses) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(SessionCard, {
					sessionId: ses.id,
					now
				}, ses.id))
			}) : null,
			challenges.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Card, { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "text-sm text-mist",
				children: "No live challenges. Load a sample, or paste one from the vendor server."
			}) }) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
				className: "space-y-3",
				children: challenges.map((c) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ChallengeCard, {
					challenge: c,
					now,
					onSign: () => void sign(c.id).then((r) => {
						if (!r.ok) toast(r.error);
						else {
							toast("Scoped session open");
							window.scrollTo({ top: 0 });
						}
					}),
					onReject: (reason) => reject(c.id, reason)
				}, c.id))
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "grid grid-cols-2 gap-2",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(GhostButton, {
						onClick: loadFresh,
						children: "Valid 60s"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(GhostButton, {
						onClick: () => loadBad("expired"),
						children: "Expired"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(GhostButton, {
						onClick: () => loadBad("audience"),
						children: "Wrong origin"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(GhostButton, {
						onClick: () => loadBad("scope"),
						children: "Extra scope"
					})
				]
			}),
			proof ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, { children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(SectionLabel, { children: "Last rehearsal proof" }),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
					className: "mt-2 text-sm text-mist",
					children: [
						"Digest over ",
						DIS_DOMAIN,
						", not an ML-DSA signature. The phone wallet still does the real sign."
					]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("dl", {
					className: "mt-2",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
							k: "Vendor",
							v: proof.vendorId
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
							k: "Key",
							v: proof.fingerprint
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
							k: "Resource",
							v: `${proof.resource} · ${proof.action}`
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
							k: "SHA-256",
							v: proof.digest
						})
					]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
					className: "mt-3",
					children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(GhostButton, {
						onClick: () => void copyText(JSON.stringify({
							domain: DIS_DOMAIN,
							suite: "ML-DSA-65",
							...proof,
							note: "rehearsal digest, not a signature"
						}, null, 2), "Proof copied"),
						children: "Copy proof"
					})
				})
			] }) : null,
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("form", {
				className: "space-y-3",
				onSubmit: (e) => {
					e.preventDefault();
					const parsed = parseChallenge(raw, Date.now());
					if ("error" in parsed) {
						setPasteError(parsed.error);
						return;
					}
					setPasteError("");
					push(parsed);
					setRaw("");
					toast("Challenge added");
				},
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
						label: "Paste challenge JSON",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("textarea", {
							value: raw,
							onChange: (e) => setRaw(e.target.value),
							rows: 4,
							placeholder: "{\"rp_id\":\"docs\",\"origin\":\"https://docs.qattice.test\",\"resource\":\"document:001\",\"scopes\":[\"document:read\"]}",
							className: "min-h-28 w-full rounded-xl border border-line bg-raised p-3 font-mono text-sm text-parchment outline-none placeholder:text-mist/70 focus:border-brass"
						})
					}),
					pasteError ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "text-sm text-clay",
						children: pasteError
					}) : null,
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(PrimaryButton, {
						type: "submit",
						disabled: !raw.trim(),
						children: "Review pasted challenge"
					})
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "mb-3 flex items-center justify-between",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(SectionLabel, { children: "Vendor keys" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
						type: "button",
						className: "text-sm text-brass",
						onClick: () => setOpen((v) => !v),
						children: open ? "Close" : "Provision"
					})]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
					className: "space-y-2",
					children: vendors.map((v) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", {
						className: "rounded-2xl border border-line bg-panel p-4",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "flex items-start justify-between gap-3",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
									className: "text-base text-parchment",
									children: v.name
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
									className: "text-sm break-all text-mist",
									children: v.origin
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
									className: "mt-1 font-mono text-sm text-brass",
									children: v.fingerprint
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
									className: "mt-1 text-sm text-mist",
									children: v.grants.join(" · ")
								})
							] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
								type: "button",
								className: "text-sm text-brass",
								onClick: () => rotate(v.id),
								children: "Rotate"
							})]
						})
					}, v.id))
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-2 text-sm text-mist",
					children: "Fingerprints differ on purpose. Rotating one vendor does not move the others."
				}),
				open ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("form", {
					className: "mt-4 space-y-3",
					onSubmit: (e) => {
						e.preventDefault();
						const result = provision(vendorId, origin, grants.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean));
						if (!result.ok) {
							setFormError(result.error);
							return;
						}
						setFormError("");
						setVendorId("");
						setOpen(false);
						toast("Vendor key provisioned");
					},
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
							label: "Vendor id",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: inputClass,
								value: vendorId,
								onChange: (e) => setVendorId(e.target.value),
								placeholder: "archive"
							})
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
							label: "Origin",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: inputClass,
								value: origin,
								onChange: (e) => setOrigin(e.target.value)
							})
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
							label: "Grants",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: inputClass,
								value: grants,
								onChange: (e) => setGrants(e.target.value)
							})
						}),
						formError ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "text-sm text-clay",
							children: formError
						}) : null,
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(PrimaryButton, {
							type: "submit",
							children: "Provision key"
						})
					]
				}) : null
			] })
		]
	});
}
function SessionCard({ sessionId, now }) {
	const session = useWallet((s) => s.sessions.find((x) => x.id === sessionId));
	const useAccess = useWallet((s) => s.useAccess);
	const endSession = useWallet((s) => s.endSession);
	const [note, setNote] = (0, import_react.useState)("");
	const [refused, setRefused] = (0, import_react.useState)(false);
	if (!session) return null;
	const left = Math.max(0, Math.ceil((session.exp - now) / 1e3));
	const label = left === 0 ? "Ended" : `${Math.floor(left / 60)}m ${String(left % 60).padStart(2, "0")}s`;
	const outside = session.scopes.includes("admin:write") ? "payment:request" : "admin:write";
	const allowed = session.scopes[0] ?? session.action;
	function act(scope) {
		const result = useAccess(sessionId, scope);
		setRefused(!result.ok);
		setNote(result.ok ? result.detail : result.error);
	}
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
		className: "rounded-2xl border border-line bg-panel p-4",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex items-center justify-between gap-3",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
					className: "text-sm text-mist",
					children: [session.vendorName, " session"]
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: left === 0 ? "text-sm text-clay" : "text-sm text-brass",
					children: label
				})]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
				className: "mt-1 text-base text-parchment",
				children: [
					session.action,
					" · ",
					session.resource
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("dl", { children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
					k: "Audience",
					v: session.origin
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
					k: "Scopes",
					v: session.scopes.join(", ")
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
					k: "Key",
					v: session.fingerprint
				})
			] }),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "mt-3 text-sm text-mist",
				children: "This grant is not signed in anywhere else, and it cannot send QCB."
			}),
			note ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: refused ? "mt-2 text-sm text-clay" : "mt-2 text-sm text-parchment",
				children: note
			}) : null,
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "mt-4 grid gap-2",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(PrimaryButton, {
						onClick: () => act(allowed),
						disabled: left === 0,
						children: ["Use ", allowed]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(GhostButton, {
						onClick: () => act(outside),
						disabled: left === 0,
						children: ["Try ", outside]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(GhostButton, {
						onClick: () => endSession(sessionId),
						children: "End session"
					})
				]
			})
		]
	});
}
function ChallengeCard({ challenge, now, onSign, onReject }) {
	const review = reviewChallenge(challenge, useWallet((s) => s.vendors), now);
	const seconds = Math.max(0, Math.ceil((challenge.exp - now) / 1e3));
	const reason = review.reasons[0] ?? "Refused";
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
		className: "rounded-2xl border border-line bg-panel p-4",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex items-center justify-between gap-3",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
					className: "text-sm text-mist",
					children: [challenge.kind === "delegated" ? "Delegated" : "Holder", " challenge"]
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
					className: seconds === 0 ? "text-sm text-clay" : "text-sm text-brass",
					children: [seconds, "s"]
				})]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("dl", {
				className: "mt-1",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
						k: "Audience",
						v: challenge.origin
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
						k: "Resource",
						v: challenge.resource
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
						k: "Action",
						v: challenge.action
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
						k: "Scopes",
						v: challenge.scopes.join(", ")
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
						k: "Nonce",
						v: challenge.nonce
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
						k: "Suite",
						v: "ML-DSA-65"
					})
				]
			}),
			review.reasons.length ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
				className: "mt-3 space-y-1",
				children: review.reasons.map((r) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", {
					className: "text-sm text-clay",
					children: r
				}, r))
			}) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "mt-3 text-sm text-mist",
				children: "Bindings match the enrolled grant. Signing still happens on the phone for real."
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "mt-4 grid grid-cols-2 gap-2",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(GhostButton, {
					onClick: () => onReject(reason),
					children: "Refuse"
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(PrimaryButton, {
					onClick: onSign,
					disabled: !review.ok,
					children: "Sign"
				})]
			})
		]
	});
}
function AddressQr({ value }) {
	const [svg, setSvg] = (0, import_react.useState)("");
	(0, import_react.useEffect)(() => {
		let live = true;
		import_lib.toString(value, {
			type: "svg",
			margin: 1,
			color: {
				dark: "#12110e",
				light: "#f3ecdf"
			}
		}).then((out) => {
			if (live) setSvg(out);
		});
		return () => {
			live = false;
		};
	}, [value]);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
		className: "qr-frame mx-auto w-52 rounded-2xl bg-parchment p-3",
		dangerouslySetInnerHTML: { __html: svg || "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 10 10'/>" }
	});
}
function MoveScreen() {
	const balance = useWallet((s) => s.balanceUqcb);
	const nonce = useWallet((s) => s.nonce);
	const send = useWallet((s) => s.send);
	const mode = useWallet((s) => s.moveMode);
	const setMode = useWallet((s) => s.setMoveMode);
	const [to, setTo] = (0, import_react.useState)("qcb1bob");
	const [amount, setAmount] = (0, import_react.useState)("1.000000");
	const [error, setError] = (0, import_react.useState)("");
	const [reviewing, setReviewing] = (0, import_react.useState)(false);
	const [digest, setDigest] = (0, import_react.useState)("");
	const uqcb = qcbToUqcb(amount);
	const body = {
		type: "Transfer",
		to: to.trim(),
		amount: uqcb ?? 0,
		denom: "uqcb"
	};
	const bodyJson = JSON.stringify(body);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "space-y-6",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(SectionLabel, { children: "Move QCB" }),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
					className: "mt-1 font-display text-3xl text-parchment",
					children: mode === "send" ? "Send" : "Receive"
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
					className: "mt-2 text-sm text-mist",
					children: [
						"Available ",
						formatQcb(balance),
						" QCB. Nonce ",
						nonce,
						". Nothing here is broadcast to the devnet."
					]
				})
			] }),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "grid grid-cols-2 gap-2",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					onClick: () => setMode("send"),
					className: `h-12 rounded-xl border text-sm font-medium ${mode === "send" ? "border-brass bg-brass text-ink" : "border-line bg-raised text-parchment"}`,
					children: "Send"
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					onClick: () => setMode("receive"),
					className: `h-12 rounded-xl border text-sm font-medium ${mode === "receive" ? "border-brass bg-brass text-ink" : "border-line bg-raised text-parchment"}`,
					children: "Receive"
				})]
			}),
			mode === "receive" ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
				className: "text-center",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(AddressQr, { value: ADDRESS }),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-4 font-mono text-sm break-all text-parchment",
						children: ADDRESS
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-2 text-sm text-mist",
						children: "qcb1pq · post-quantum account. Pay in uQCB."
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
						className: "mt-4",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(PrimaryButton, {
							onClick: () => void copyText(ADDRESS, "Address copied"),
							children: "Copy address"
						})
					})
				]
			}) : /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("form", {
				className: "space-y-3",
				onSubmit: (e) => {
					e.preventDefault();
					if (uqcb == null) {
						setError("Use up to 6 decimal places. 1 QCB = 1,000,000 uQCB.");
						setReviewing(false);
						return;
					}
					setError("");
					setReviewing(true);
				},
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
						label: "To",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
							className: inputClass,
							value: to,
							onChange: (e) => {
								setTo(e.target.value);
								setReviewing(false);
							}
						})
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
						label: "Amount in QCB",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
							className: inputClass,
							inputMode: "decimal",
							value: amount,
							onChange: (e) => {
								setAmount(e.target.value);
								setReviewing(false);
								setDigest("");
							}
						})
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "text-sm text-mist",
						children: uqcb == null ? "Amount not readable yet." : formatUqcb(uqcb)
					}),
					error ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "text-sm text-clay",
						children: error
					}) : null,
					!reviewing ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(PrimaryButton, {
						type: "submit",
						children: "Review envelope"
					}) : null
				]
			}),
			mode === "send" && reviewing && uqcb != null ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, { children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(SectionLabel, { children: "SignedTxEnvelope" }),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("dl", {
					className: "mt-2",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
							k: "chain_id",
							v: CHAIN_ID
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
							k: "sender",
							v: shortAddress(ADDRESS)
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
							k: "nonce",
							v: String(nonce)
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
							k: "gas_limit",
							v: GAS_LIMIT.toLocaleString("en-US")
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
							k: "denom",
							v: "uqcb"
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
							k: "prehash",
							v: `${TX_DOMAIN} + chain id + body`
						})
					]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("pre", {
					className: "mt-3 overflow-x-auto rounded-xl bg-raised p-3 font-mono text-xs text-mist",
					children: txPreimage(bodyJson)
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-3 text-sm text-mist",
					children: "The real wallet signs that preimage with ML-DSA-65 and submits only the envelope to /api/tx."
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
					className: "mt-4",
					children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(PrimaryButton, {
						onClick: () => void send(to, uqcb).then((r) => {
							if (!r.ok) {
								setError(r.error);
								return;
							}
							setDigest(r.digest);
							setReviewing(false);
							toast("Transfer recorded");
						}),
						children: "Record rehearsal send"
					})
				})
			] }) : null,
			digest ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, { children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(SectionLabel, { children: "Rehearsal digest" }),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-2 font-mono text-sm break-all text-parchment",
					children: digest
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-2 text-sm text-mist",
					children: "SHA-256 of the preimage. Not a signature, and not submitted."
				})
			] }) : null
		]
	});
}
var SCOPE_CHOICES = [
	"document:read",
	"payment:request",
	"agent:spawn",
	"agent:spend"
];
function AgentsScreen() {
	const agents = useWallet((s) => s.agents);
	const sponsored = useWallet((s) => s.sponsored);
	const tier = useWallet((s) => s.tier);
	const ask = useWallet((s) => s.ask);
	const approve = useWallet((s) => s.approveAsk);
	const deny = useWallet((s) => s.denyAsk);
	const revoke = useWallet((s) => s.revokeAgent);
	const add = useWallet((s) => s.addAgent);
	const sponsor = useWallet((s) => s.sponsor);
	const revokeSponsored = useWallet((s) => s.revokeSponsored);
	const [name, setName] = (0, import_react.useState)("");
	const [scopes, setScopes] = (0, import_react.useState)(["document:read"]);
	const [uses, setUses] = (0, import_react.useState)("3");
	const [cap, setCap] = (0, import_react.useState)("0.500000");
	const [error, setError] = (0, import_react.useState)("");
	const [kind, setKind] = (0, import_react.useState)("agent");
	const [sponsorName, setSponsorName] = (0, import_react.useState)("");
	const [purpose, setPurpose] = (0, import_react.useState)("");
	const [sponsorCap, setSponsorCap] = (0, import_react.useState)("0.250000");
	const [sponsorError, setSponsorError] = (0, import_react.useState)("");
	const waiting = ask ? agents.find((a) => a.id === ask.agentId) : void 0;
	const verified = tier === "verified";
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "space-y-6",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(SectionLabel, { children: "Charmed agents" }),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
					className: "mt-1 font-display text-3xl text-parchment",
					children: "Sponsor, then delegate"
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-2 text-sm text-mist",
					children: "Sponsorship needs a verified human and stamps your qcb1pq address on the agent or contract. Delegation is narrower, and it does not prove personhood."
				})
			] }),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, { children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(SectionLabel, { children: "Sponsor desk" }),
				verified ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
					className: "mt-2 text-sm text-mist",
					children: [
						"Sponsor id ",
						shortAddress(ADDRESS),
						". Nothing here is deployed to the devnet."
					]
				}) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-2 text-sm text-clay",
					children: "Locked. Only a verified human can sponsor. A vendor session will not do it."
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "mt-4 grid grid-cols-2 gap-2",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
						type: "button",
						onClick: () => setKind("agent"),
						className: `h-12 rounded-xl border text-sm font-medium ${kind === "agent" ? "border-brass bg-brass text-ink" : "border-line bg-raised text-parchment"}`,
						children: "Agent"
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
						type: "button",
						onClick: () => setKind("contract"),
						className: `h-12 rounded-xl border text-sm font-medium ${kind === "contract" ? "border-brass bg-brass text-ink" : "border-line bg-raised text-parchment"}`,
						children: "Contract"
					})]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("form", {
					className: "mt-3 space-y-3",
					onSubmit: (e) => {
						e.preventDefault();
						const capU = kind === "agent" ? qcbToUqcb(sponsorCap) : null;
						if (kind === "agent" && capU == null) {
							setSponsorError("Spending cap needs up to 6 decimals.");
							return;
						}
						const result = sponsor(kind, sponsorName, purpose, capU);
						if (!result.ok) {
							setSponsorError(result.error);
							return;
						}
						setSponsorError("");
						setSponsorName("");
						setPurpose("");
						toast(kind === "agent" ? "Agent sponsored" : "Contract sponsored");
					},
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
							label: "Name",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: inputClass,
								value: sponsorName,
								onChange: (e) => setSponsorName(e.target.value),
								placeholder: kind === "agent" ? "Archivist" : "Escrow terms",
								disabled: !verified
							})
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
							label: "Purpose",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: inputClass,
								value: purpose,
								onChange: (e) => setPurpose(e.target.value),
								placeholder: kind === "agent" ? "Reads documents you already granted" : "Holds a job payment until both sides sign",
								disabled: !verified
							})
						}),
						kind === "agent" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
							label: "Spend cap QCB",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: inputClass,
								inputMode: "decimal",
								value: sponsorCap,
								onChange: (e) => setSponsorCap(e.target.value),
								disabled: !verified
							})
						}) : null,
						sponsorError ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "text-sm text-clay",
							children: sponsorError
						}) : null,
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(PrimaryButton, {
							type: "submit",
							disabled: !verified,
							children: kind === "agent" ? "Sponsor agent" : "Sponsor contract"
						})
					]
				}),
				sponsored.length > 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
					className: "mt-4 space-y-2 border-t border-line pt-3",
					children: sponsored.map((item) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", { children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "flex items-start justify-between gap-3",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "text-base text-parchment",
								children: item.name
							}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
								className: "text-sm text-mist",
								children: [item.kind === "agent" ? "Sponsored agent" : "Sponsored contract", item.status === "revoked" ? " · revoked" : ""]
							})] }), item.status === "active" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
								type: "button",
								className: "text-sm text-clay",
								onClick: () => revokeSponsored(item.id),
								children: "Revoke"
							}) : null]
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "mt-1 text-sm text-parchment",
							children: item.purpose
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
							className: "mt-1 text-sm text-mist",
							children: [
								"Sponsor ",
								shortAddress(ADDRESS),
								item.kind === "agent" ? ` · cap ${formatQcb(item.spendCapUqcb)} QCB` : ""
							]
						})
					] }, item.id))
				}) : null
			] }),
			ask && waiting ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, { children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(SectionLabel, { children: "Human gate" }),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
					className: "mt-2 text-base text-parchment",
					children: [
						waiting.name,
						" wants to ",
						ask.action,
						" ",
						formatUqcb(ask.spendUqcb)
					]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("dl", { children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
						k: "Resource",
						v: ask.resource
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
						k: "Scope",
						v: ask.scopes.join(", ")
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
						k: "Uses left",
						v: `${waiting.maxUses - waiting.uses} of ${waiting.maxUses}`
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Row, {
						k: "Cap left",
						v: formatUqcb(waiting.spendCapUqcb - waiting.spentUqcb)
					})
				] }),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "mt-4 grid grid-cols-2 gap-2",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(GhostButton, {
						onClick: deny,
						children: "Deny"
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(PrimaryButton, {
						onClick: () => {
							const result = approve();
							toast(result.ok ? "Spend approved" : result.error);
						},
						children: "Approve"
					})]
				})
			] }) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Card, { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "text-sm text-mist",
				children: "No spend is waiting on you."
			}) }),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
				className: "space-y-2",
				children: agents.map((a) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
					className: "rounded-2xl border border-line bg-panel p-4",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "flex items-start justify-between gap-3",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "text-base text-parchment",
								children: a.name
							}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
								className: "text-sm text-mist",
								children: [a.status === "revoked" ? "Revoked" : "Delegated", " · depth 1"]
							})] }), a.status === "active" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
								type: "button",
								className: "text-sm text-clay",
								onClick: () => revoke(a.id),
								children: "Revoke"
							}) : null]
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "mt-2 text-sm text-parchment",
							children: a.scopes.join(" · ")
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
							className: "mt-1 text-sm text-mist",
							children: [
								a.uses,
								" of ",
								a.maxUses,
								" uses · spent ",
								formatQcb(a.spentUqcb),
								" of ",
								formatQcb(a.spendCapUqcb),
								" QCB"
							]
						})
					]
				}, a.id))
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("form", {
				className: "space-y-3",
				onSubmit: (e) => {
					e.preventDefault();
					const capU = qcbToUqcb(cap);
					const maxUses = Number(uses);
					if (capU == null) {
						setError("Spending cap needs up to 6 decimals.");
						return;
					}
					const result = add(name, scopes, maxUses, capU);
					if (!result.ok) {
						setError(result.error);
						return;
					}
					setError("");
					setName("");
					toast("Agent delegated");
				},
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(SectionLabel, { children: "New delegation" }),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
						label: "Name",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
							className: inputClass,
							value: name,
							onChange: (e) => setName(e.target.value),
							placeholder: "Archivist"
						})
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("fieldset", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("legend", {
						className: "mb-2 text-xs font-medium tracking-wide text-mist uppercase",
						children: "Scopes"
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
						className: "grid grid-cols-2 gap-2",
						children: SCOPE_CHOICES.map((scope) => {
							const on = scopes.includes(scope);
							return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
								type: "button",
								onClick: () => setScopes((cur) => cur.includes(scope) ? cur.filter((s) => s !== scope) : [...cur, scope]),
								className: `h-12 rounded-xl border px-2 text-sm ${on ? "border-brass bg-brass text-ink" : "border-line bg-raised text-parchment"}`,
								children: scope
							}, scope);
						})
					})] }),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "grid grid-cols-2 gap-2",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
							label: "max_uses",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: inputClass,
								inputMode: "numeric",
								value: uses,
								onChange: (e) => setUses(e.target.value)
							})
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
							label: "Spend cap QCB",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: inputClass,
								inputMode: "decimal",
								value: cap,
								onChange: (e) => setCap(e.target.value)
							})
						})]
					}),
					error ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "text-sm text-clay",
						children: error
					}) : null,
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(PrimaryButton, {
						type: "submit",
						children: "Delegate"
					})
				]
			})
		]
	});
}
var FILTERS = [
	{
		id: "all",
		label: "All"
	},
	{
		id: "phone",
		label: "On the phone"
	},
	{
		id: "next",
		label: "Build next"
	},
	{
		id: "gate",
		label: "Not yet"
	}
];
function SpecScreen({ go }) {
	const rehearsed = useWallet((s) => s.rehearsed);
	const reset = useWallet((s) => s.reset);
	const [filter, setFilter] = (0, import_react.useState)("all");
	const items = SPEC.filter((item) => filter === "all" || item.group === filter);
	const brief = SPEC.map((item) => `${item.group.toUpperCase()} — ${item.title}\n${item.detail}`).join("\n\n");
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "space-y-6",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(SectionLabel, { children: "Required spec" }),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
					className: "mt-1 font-display text-3xl text-parchment",
					children: "What the wallet still owes"
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-2 text-sm text-mist",
					children: "Taken from chain-forge-engine: the Android reference client, chain-forge-wallet, and the DIS return gates. Rehearsed items are flows you have already walked here."
				})
			] }),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: "grid grid-cols-2 gap-2",
				children: FILTERS.map((f) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					onClick: () => setFilter(f.id),
					className: `h-12 rounded-xl border text-sm ${filter === f.id ? "border-brass bg-brass text-ink" : "border-line bg-panel text-parchment"}`,
					children: f.label
				}, f.id))
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
				className: "space-y-3",
				children: items.map((item) => {
					const done = item.rehearsal ? rehearsed.includes(item.rehearsal) : false;
					const label = item.group === "phone" ? "On phone" : item.group === "gate" ? "Return gate" : done ? "Rehearsed" : "Needed";
					return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
						className: "rounded-2xl border border-line bg-panel p-4",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "flex items-center justify-between gap-3",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
									className: "text-xs tracking-wide text-mist uppercase",
									children: label
								}), item.surface ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
									type: "button",
									className: "text-sm text-brass",
									onClick: () => go(item.surface),
									children: "Open"
								}) : null]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "mt-1 text-base text-parchment",
								children: item.title
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "mt-1 text-sm text-mist",
								children: item.detail
							})
						]
					}, item.id);
				})
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)(GhostButton, {
				onClick: () => void copyText(brief, "Build brief copied"),
				children: "Copy build brief"
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
				type: "button",
				className: "block text-sm text-mist",
				onClick: reset,
				children: "Reset rehearsal"
			})
		]
	});
}
var NAV = [
	{
		id: "home",
		label: "Home",
		icon: Hexagon
	},
	{
		id: "stone",
		label: "Stone",
		icon: Fingerprint
	},
	{
		id: "move",
		label: "Move",
		icon: ArrowLeftRight
	},
	{
		id: "agents",
		label: "Agents",
		icon: Bot
	},
	{
		id: "spec",
		label: "Spec",
		icon: ListChecks
	}
];
function QatticeApp() {
	const tab = useWallet((s) => s.tab);
	const setTab = useWallet((s) => s.setTab);
	(0, import_react.useEffect)(() => {
		useWallet.persist.rehydrate();
	}, []);
	function go(next) {
		setTab(next);
		window.scrollTo({ top: 0 });
	}
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "lattice min-h-dvh text-parchment",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("main", {
				className: "mx-auto min-h-dvh w-full max-w-md px-4 pt-6 pb-28",
				children: [
					tab === "home" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(HomeScreen, { go }) : null,
					tab === "stone" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(StoneScreen, {}) : null,
					tab === "move" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(MoveScreen, {}) : null,
					tab === "agents" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(AgentsScreen, {}) : null,
					tab === "spec" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(SpecScreen, { go }) : null
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("nav", {
				className: "fixed inset-x-0 bottom-0 z-10",
				children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
					className: "mx-auto grid h-16 max-w-md grid-cols-5 border-t border-line bg-ink",
					children: NAV.map((item) => {
						const Icon = item.icon;
						const on = tab === item.id;
						return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
							type: "button",
							onClick: () => go(item.id),
							className: `flex flex-col items-center justify-center gap-0.5 text-xs ${on ? "text-brass" : "text-mist"}`,
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Icon, {
								size: 18,
								strokeWidth: 1.75,
								"aria-hidden": true
							}), item.label]
						}, item.id);
					})
				})
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Toaster, {
				theme: "dark",
				position: "top-center",
				toastOptions: { style: {
					background: "var(--color-panel)",
					color: "var(--color-parchment)",
					border: "1px solid var(--color-line)"
				} }
			})
		]
	});
}
function Home() {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(QatticeApp, {});
}
//#endregion
export { Home as component };
