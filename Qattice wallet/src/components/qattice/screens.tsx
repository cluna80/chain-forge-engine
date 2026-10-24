import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { toast } from "sonner";
import { getAddress } from "@/lib/keypair-store";
import {
  ATTESTATION_QUORUM,
  CHAIN_ID,
  DIS_DOMAIN,
  GAS_LIMIT,
  NODE_URL,
  SPEC,
  TX_DOMAIN,
  PROPOSAL,
  REWARD_UQCB,
  UQCB,
  formatQcb,
  formatUqcb,
  parseChallenge,
  reviewChallenge,
  shortAddress,
  txPreimage,
  type Challenge,
  type SpecGroup,
  type Tab,
} from "@/lib/qattice";
import { useWallet } from "@/lib/wallet-store";
import { Card, Field, GhostButton, Mark, PrimaryButton, Row, SectionLabel, copyText, inputClass } from "@/components/qattice/ui";

function useNow(active: boolean) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [active]);
  return now;
}

function ago(at: number) {
  const s = Math.max(0, Math.round((Date.now() - at) / 1000));
  if (s < 60) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

function qcbToUqcb(input: string) {
  const t = input.trim();
  if (!/^\d+(\.\d{0,6})?$/.test(t)) return null;
  const [w, f = ""] = t.split(".");
  const frac = (f + "000000").slice(0, 6);
  const n = Number(w) * UQCB + Number(frac);
  if (!Number.isSafeInteger(n) || n <= 0) return null;
  return n;
}

export function HomeScreen({ go }: { go: (tab: Tab) => void }) {
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
  const sessions = useWallet((s) => s.sessions);
  const nodeConnected = useWallet((s) => s.nodeConnected);
  const nodeError = useWallet((s) => s.nodeError);
  const syncFromNode = useWallet((s) => s.syncFromNode);
  const openSessions = sessions.filter((ses) => ses.exp > Date.now());

  useEffect(() => {
    void syncFromNode();
  }, [syncFromNode]);

  const nodeLabel = nodeConnected === null
    ? "connecting…"
    : nodeConnected
    ? "node live"
    : "rehearsal mode";

  return (
    <div className="space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-brass">
            <Mark className="h-7 w-7" />
            <h1 className="font-display text-3xl font-medium tracking-tight text-parchment">Qattice</h1>
          </div>
          <p className="mt-1 text-sm text-mist">{NODE_URL ? "Live wallet" : "Rehearsal wallet"} · keys stay on the phone</p>
        </div>
        <div className="flex flex-col items-end gap-1">
          <p className="rounded-full border border-line px-3 py-1 text-xs text-mist">{CHAIN_ID.replace("qcb-", "")}</p>
          <p
            className={`text-xs ${nodeConnected === true ? "text-brass" : nodeConnected === false ? "text-clay" : "text-mist"}`}
            title={nodeError ?? undefined}
          >
            {nodeLabel}
          </p>
        </div>
      </header>

      <div>
        <p className="font-display text-4xl font-medium tracking-tight text-parchment">{formatQcb(balance)}</p>
        <p className="mt-1 text-sm text-mist">QCB · {formatUqcb(balance)}</p>
      </div>

      <button
        type="button"
        onClick={() => void copyText(getAddress(), "Address copied")}
        className="flex w-full items-center justify-between rounded-2xl border border-line bg-panel px-4 py-3 text-left"
      >
        <span>
          <span className="block text-xs text-mist">Chain account</span>
          <span className="font-mono text-sm text-parchment">{shortAddress(getAddress())}</span>
        </span>
        <span className="text-sm text-brass">Copy</span>
      </button>

      <Card>
        <div className="flex items-start justify-between gap-3">
          <div>
            <SectionLabel>Identity tier</SectionLabel>
            <p className="mt-1 font-display text-2xl text-parchment capitalize">{tier}</p>
            <p className="mt-1 text-sm text-mist">
              {attestations} of {ATTESTATION_QUORUM} attestations. A DIS login is not personhood.
            </p>
          </div>
          <span className="mt-1 h-2.5 w-2.5 rounded-full bg-brass" aria-hidden />
        </div>
        {tier === "provisional" ? (
          <div className="mt-4">
            <PrimaryButton
              onClick={() =>
                void attest().then((r) => {
                  if (!r.ok) toast(r.error);
                  else toast(NODE_URL ? "Attest tx submitted" : "Attestation recorded");
                })
              }
            >
              Record attestation
            </PrimaryButton>
          </div>
        ) : (
          <div className="mt-4">
            <p className="text-sm text-mist">Quorum met. Sponsorship uses this identity, not a Docs session.</p>
            <div className="mt-3">
              <GhostButton onClick={() => go("agents")}>Open sponsor desk</GhostButton>
            </div>
          </div>
        )}
      </Card>

      <Card>
        <SectionLabel>Participation</SectionLabel>
        <p className="mt-2 text-base text-parchment">{PROPOSAL.title}</p>
        <p className="mt-1 text-sm text-mist">{PROPOSAL.detail}</p>
        {vote ? (
          <p className="mt-3 text-sm text-parchment">You voted {vote}. It counts once.</p>
        ) : (
          <div className="mt-4 grid grid-cols-2 gap-2">
            <GhostButton
              disabled={tier !== "verified"}
              onClick={() => {
                const result = castVote("yes");
                if (!result.ok) toast(result.error);
              }}
            >
              Vote yes
            </GhostButton>
            <GhostButton
              disabled={tier !== "verified"}
              onClick={() => {
                const result = castVote("no");
                if (!result.ok) toast(result.error);
              }}
            >
              Vote no
            </GhostButton>
          </div>
        )}
        <div className="mt-3">
          {claimed ? (
            <p className="text-sm text-parchment">Reward claimed · {formatQcb(REWARD_UQCB)} QCB</p>
          ) : (
            <PrimaryButton
              disabled={tier !== "verified"}
              onClick={() => {
                const result = claim();
                if (!result.ok) toast(result.error);
                else toast("Reward claimed");
              }}
            >
              Claim {formatQcb(REWARD_UQCB)} QCB
            </PrimaryButton>
          )}
        </div>
        {tier !== "verified" ? (
          <p className="mt-3 text-sm text-mist">Locked until {ATTESTATION_QUORUM} attestations. Signing in to Docs will not open this.</p>
        ) : null}
      </Card>

      <div className="grid grid-cols-3 gap-2">
        <GhostButton onClick={() => { setMoveMode("send"); go("move"); }}>Send</GhostButton>
        <GhostButton onClick={() => { setMoveMode("receive"); go("move"); }}>Receive</GhostButton>
        <GhostButton onClick={() => go("stone")}>Sign</GhostButton>
      </div>

      <div className="grid gap-3">
        <p className="text-sm text-mist">
          <span className="text-parchment">Chain key. </span>
          One qcb1pq address signs QCB transfers. Nonce lives on the account.
        </p>
        <p className="text-sm text-mist">
          <span className="text-parchment">{vendors.length} vendor keys. </span>
          Each relying party has its own ML-DSA fingerprint. They are not this address.
        </p>
        {openSessions.length > 0 ? (
          <p className="text-sm text-mist">
            <span className="text-parchment">{openSessions.length} vendor session{openSessions.length === 1 ? "" : "s"}. </span>
            {openSessions.map((ses) => ses.vendorName).join(", ")} can use their grant. They cannot spend this balance.
          </p>
        ) : null}
      </div>

      <div>
        <SectionLabel>Recent</SectionLabel>
        <ul className="mt-3 divide-y divide-line">
          {activity.slice(0, 5).map((item) => (
            <li key={item.id} className="py-3">
              <p className="text-sm text-parchment">{item.title}</p>
              <p className="text-sm text-mist">{item.detail}</p>
              <p className="text-xs text-mist">{ago(item.at)}</p>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export function StoneScreen() {
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
  const [raw, setRaw] = useState("");
  const [pasteError, setPasteError] = useState("");
  const [vendorId, setVendorId] = useState("");
  const [origin, setOrigin] = useState("https://");
  const [grants, setGrants] = useState("document:read");
  const [formError, setFormError] = useState("");
  const [open, setOpen] = useState(false);

  return (
    <div className="space-y-6">
      <div>
        <SectionLabel>Digital Identity Stone</SectionLabel>
        <h2 className="mt-1 font-display text-3xl text-parchment">Sign what you can read</h2>
        <p className="mt-2 text-sm text-mist">
          The phone test wallet signs whatever JSON is in the box. A good signature here opens one vendor grant. It is not a chain login, and it does not move QCB.
        </p>
      </div>

      {sessions.length > 0 ? (
        <ul className="space-y-3">
          {sessions.map((ses) => (
            <SessionCard key={ses.id} sessionId={ses.id} now={now} />
          ))}
        </ul>
      ) : null}

      {challenges.length === 0 ? (
        <Card>
          <p className="text-sm text-mist">No live challenges. Load a sample, or paste one from the vendor server.</p>
        </Card>
      ) : (
        <ul className="space-y-3">
          {challenges.map((c) => (
            <ChallengeCard
              key={c.id}
              challenge={c}
              now={now}
              onSign={() =>
                void sign(c.id).then((r) => {
                  if (!r.ok) toast(r.error);
                  else {
                    toast("Scoped session open");
                    window.scrollTo({ top: 0 });
                  }
                })
              }
              onReject={(reason) => reject(c.id, reason)}
            />
          ))}
        </ul>
      )}

      <div className="grid grid-cols-2 gap-2">
        <GhostButton onClick={loadFresh}>Valid 60s</GhostButton>
        <GhostButton onClick={() => loadBad("expired")}>Expired</GhostButton>
        <GhostButton onClick={() => loadBad("audience")}>Wrong origin</GhostButton>
        <GhostButton onClick={() => loadBad("scope")}>Extra scope</GhostButton>
      </div>

      {proof ? (
        <Card>
          <SectionLabel>Last rehearsal proof</SectionLabel>
          <p className="mt-2 text-sm text-mist">
            Digest over {DIS_DOMAIN}, not an ML-DSA signature. The phone wallet still does the real sign.
          </p>
          <dl className="mt-2">
            <Row k="Vendor" v={proof.vendorId} />
            <Row k="Key" v={proof.fingerprint} />
            <Row k="Resource" v={`${proof.resource} · ${proof.action}`} />
            <Row k="SHA-256" v={proof.digest} />
          </dl>
          <div className="mt-3">
            <GhostButton
              onClick={() =>
                void copyText(
                  JSON.stringify(
                    {
                      domain: DIS_DOMAIN,
                      suite: "ML-DSA-65",
                      ...proof,
                      note: "rehearsal digest, not a signature",
                    },
                    null,
                    2,
                  ),
                  "Proof copied",
                )
              }
            >
              Copy proof
            </GhostButton>
          </div>
        </Card>
      ) : null}

      <form
        className="space-y-3"
        onSubmit={(e) => {
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
        }}
      >
        <Field label="Paste challenge JSON">
          <textarea
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
            rows={4}
            placeholder='{"rp_id":"docs","origin":"https://docs.qattice.test","resource":"document:001","scopes":["document:read"]}'
            className="min-h-28 w-full rounded-xl border border-line bg-raised p-3 font-mono text-sm text-parchment outline-none placeholder:text-mist/70 focus:border-brass"
          />
        </Field>
        {pasteError ? <p className="text-sm text-clay">{pasteError}</p> : null}
        <PrimaryButton type="submit" disabled={!raw.trim()}>
          Review pasted challenge
        </PrimaryButton>
      </form>

      <div>
        <div className="mb-3 flex items-center justify-between">
          <SectionLabel>Vendor keys</SectionLabel>
          <button type="button" className="text-sm text-brass" onClick={() => setOpen((v) => !v)}>
            {open ? "Close" : "Provision"}
          </button>
        </div>
        <ul className="space-y-2">
          {vendors.map((v) => (
            <li key={v.id} className="rounded-2xl border border-line bg-panel p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-base text-parchment">{v.name}</p>
                  <p className="text-sm break-all text-mist">{v.origin}</p>
                  <p className="mt-1 font-mono text-sm text-brass">{v.fingerprint}</p>
                  <p className="mt-1 text-sm text-mist">{v.grants.join(" · ")}</p>
                </div>
                <button type="button" className="text-sm text-brass" onClick={() => rotate(v.id)}>
                  Rotate
                </button>
              </div>
            </li>
          ))}
        </ul>
        <p className="mt-2 text-sm text-mist">Fingerprints differ on purpose. Rotating one vendor does not move the others.</p>
        {open ? (
          <form
            className="mt-4 space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              const result = provision(
                vendorId,
                origin,
                grants.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean),
              );
              if (!result.ok) {
                setFormError(result.error);
                return;
              }
              setFormError("");
              setVendorId("");
              setOpen(false);
              toast("Vendor key provisioned");
            }}
          >
            <Field label="Vendor id">
              <input className={inputClass} value={vendorId} onChange={(e) => setVendorId(e.target.value)} placeholder="archive" />
            </Field>
            <Field label="Origin">
              <input className={inputClass} value={origin} onChange={(e) => setOrigin(e.target.value)} />
            </Field>
            <Field label="Grants">
              <input className={inputClass} value={grants} onChange={(e) => setGrants(e.target.value)} />
            </Field>
            {formError ? <p className="text-sm text-clay">{formError}</p> : null}
            <PrimaryButton type="submit">Provision key</PrimaryButton>
          </form>
        ) : null}
      </div>
    </div>
  );
}

function SessionCard({ sessionId, now }: { sessionId: string; now: number }) {
  const session = useWallet((s) => s.sessions.find((x) => x.id === sessionId));
  const useAccess = useWallet((s) => s.useAccess);
  const endSession = useWallet((s) => s.endSession);
  const [note, setNote] = useState("");
  const [refused, setRefused] = useState(false);
  if (!session) return null;
  const left = Math.max(0, Math.ceil((session.exp - now) / 1000));
  const label = left === 0 ? "Ended" : `${Math.floor(left / 60)}m ${String(left % 60).padStart(2, "0")}s`;
  const outside = session.scopes.includes("admin:write") ? "payment:request" : "admin:write";
  const allowed = session.scopes[0] ?? session.action;

  function act(scope: string) {
    const result = useAccess(sessionId, scope);
    setRefused(!result.ok);
    setNote(result.ok ? result.detail : result.error);
  }

  return (
    <li className="rounded-2xl border border-line bg-panel p-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm text-mist">{session.vendorName} session</p>
        <p className={left === 0 ? "text-sm text-clay" : "text-sm text-brass"}>{label}</p>
      </div>
      <p className="mt-1 text-base text-parchment">
        {session.action} · {session.resource}
      </p>
      <dl>
        <Row k="Audience" v={session.origin} />
        <Row k="Scopes" v={session.scopes.join(", ")} />
        <Row k="Key" v={session.fingerprint} />
      </dl>
      <p className="mt-3 text-sm text-mist">This grant is not signed in anywhere else, and it cannot send QCB.</p>
      {note ? <p className={refused ? "mt-2 text-sm text-clay" : "mt-2 text-sm text-parchment"}>{note}</p> : null}
      <div className="mt-4 grid gap-2">
        <PrimaryButton onClick={() => act(allowed)} disabled={left === 0}>
          Use {allowed}
        </PrimaryButton>
        <GhostButton onClick={() => act(outside)} disabled={left === 0}>
          Try {outside}
        </GhostButton>
        <GhostButton onClick={() => endSession(sessionId)}>End session</GhostButton>
      </div>
    </li>
  );
}

function ChallengeCard({
  challenge,
  now,
  onSign,
  onReject,
}: {
  challenge: Challenge;
  now: number;
  onSign: () => void;
  onReject: (reason: string) => void;
}) {
  const vendors = useWallet((s) => s.vendors);
  const review = reviewChallenge(challenge, vendors, now);
  const seconds = Math.max(0, Math.ceil((challenge.exp - now) / 1000));
  const reason = review.reasons[0] ?? "Refused";

  return (
    <li className="rounded-2xl border border-line bg-panel p-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm text-mist">{challenge.kind === "delegated" ? "Delegated" : "Holder"} challenge</p>
        <p className={seconds === 0 ? "text-sm text-clay" : "text-sm text-brass"}>{seconds}s</p>
      </div>
      <dl className="mt-1">
        <Row k="Audience" v={challenge.origin} />
        <Row k="Resource" v={challenge.resource} />
        <Row k="Action" v={challenge.action} />
        <Row k="Scopes" v={challenge.scopes.join(", ")} />
        <Row k="Nonce" v={challenge.nonce} />
        <Row k="Suite" v="ML-DSA-65" />
      </dl>
      {review.reasons.length ? (
        <ul className="mt-3 space-y-1">
          {review.reasons.map((r) => (
            <li key={r} className="text-sm text-clay">
              {r}
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-3 text-sm text-mist">Bindings match the enrolled grant. Signing still happens on the phone for real.</p>
      )}
      <div className="mt-4 grid grid-cols-2 gap-2">
        <GhostButton onClick={() => onReject(reason)}>Refuse</GhostButton>
        <PrimaryButton onClick={onSign} disabled={!review.ok}>
          Sign
        </PrimaryButton>
      </div>
    </li>
  );
}

function AddressQr({ value }: { value: string }) {
  const [svg, setSvg] = useState("");
  useEffect(() => {
    let live = true;
    void QRCode.toString(value, {
      type: "svg",
      margin: 1,
      color: { dark: "#12110e", light: "#f3ecdf" },
    }).then((out) => {
      if (live) setSvg(out);
    });
    return () => {
      live = false;
    };
  }, [value]);
  return (
    <div
      className="qr-frame mx-auto w-52 rounded-2xl bg-parchment p-3"
      dangerouslySetInnerHTML={{ __html: svg || "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 10 10'/>" }}
    />
  );
}

export function MoveScreen() {
  const balance = useWallet((s) => s.balanceUqcb);
  const nonce = useWallet((s) => s.nonce);
  const send = useWallet((s) => s.send);
  const mode = useWallet((s) => s.moveMode);
  const setMode = useWallet((s) => s.setMoveMode);
  const [to, setTo] = useState("qcb1bob");
  const [amount, setAmount] = useState("1.000000");
  const [error, setError] = useState("");
  const [reviewing, setReviewing] = useState(false);
  const [digest, setDigest] = useState("");

  const uqcb = qcbToUqcb(amount);
  const body = {
    type: "Transfer",
    to: to.trim(),
    amount: uqcb ?? 0,
    denom: "uqcb",
  };
  const bodyJson = JSON.stringify(body);

  return (
    <div className="space-y-6">
      <div>
        <SectionLabel>Move QCB</SectionLabel>
        <h2 className="mt-1 font-display text-3xl text-parchment">
          {mode === "send" ? "Send" : "Receive"}
        </h2>
        <p className="mt-2 text-sm text-mist">
          Available {formatQcb(balance)} QCB. Nonce {nonce}. Nothing here is broadcast to the devnet.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-2">
        <button
          type="button"
          onClick={() => setMode("send")}
          className={`h-12 rounded-xl border text-sm font-medium ${mode === "send" ? "border-brass bg-brass text-ink" : "border-line bg-raised text-parchment"}`}
        >
          Send
        </button>
        <button
          type="button"
          onClick={() => setMode("receive")}
          className={`h-12 rounded-xl border text-sm font-medium ${mode === "receive" ? "border-brass bg-brass text-ink" : "border-line bg-raised text-parchment"}`}
        >
          Receive
        </button>
      </div>

      {mode === "receive" ? (
        <Card className="text-center">
          <AddressQr value={getAddress()} />
          <p className="mt-4 font-mono text-sm break-all text-parchment">{getAddress()}</p>
          <p className="mt-2 text-sm text-mist">qcb1pq · post-quantum account. Pay in uQCB.</p>
          <div className="mt-4">
            <PrimaryButton onClick={() => void copyText(getAddress(), "Address copied")}>Copy address</PrimaryButton>
          </div>
        </Card>
      ) : (
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (uqcb == null) {
              setError("Use up to 6 decimal places. 1 QCB = 1,000,000 uQCB.");
              setReviewing(false);
              return;
            }
            setError("");
            setReviewing(true);
          }}
        >
          <Field label="To">
            <input className={inputClass} value={to} onChange={(e) => { setTo(e.target.value); setReviewing(false); }} />
          </Field>
          <Field label="Amount in QCB">
            <input
              className={inputClass}
              inputMode="decimal"
              value={amount}
              onChange={(e) => {
                setAmount(e.target.value);
                setReviewing(false);
                setDigest("");
              }}
            />
          </Field>
          <p className="text-sm text-mist">{uqcb == null ? "Amount not readable yet." : formatUqcb(uqcb)}</p>
          {error ? <p className="text-sm text-clay">{error}</p> : null}
          {!reviewing ? <PrimaryButton type="submit">Review envelope</PrimaryButton> : null}
        </form>
      )}

      {mode === "send" && reviewing && uqcb != null ? (
        <Card>
          <SectionLabel>SignedTxEnvelope</SectionLabel>
          <dl className="mt-2">
            <Row k="chain_id" v={CHAIN_ID} />
            <Row k="sender" v={shortAddress(getAddress())} />
            <Row k="nonce" v={String(nonce)} />
            <Row k="gas_limit" v={GAS_LIMIT.toLocaleString("en-US")} />
            <Row k="denom" v="uqcb" />
            <Row k="prehash" v={`${TX_DOMAIN} + chain id + body`} />
          </dl>
          <pre className="mt-3 overflow-x-auto rounded-xl bg-raised p-3 font-mono text-xs text-mist">{txPreimage(bodyJson)}</pre>
          <p className="mt-3 text-sm text-mist">
            The real wallet signs that preimage with ML-DSA-65 and submits only the envelope to /api/tx.
          </p>
          <div className="mt-4">
            <PrimaryButton
              onClick={() =>
                void send(to, uqcb).then((r) => {
                  if (!r.ok) {
                    setError(r.error);
                    return;
                  }
                  setDigest(r.digest);
                  setReviewing(false);
                  toast("Transfer recorded");
                })
              }
            >
              Record rehearsal send
            </PrimaryButton>
          </div>
        </Card>
      ) : null}

      {digest ? (
        <Card>
          <SectionLabel>Rehearsal digest</SectionLabel>
          <p className="mt-2 font-mono text-sm break-all text-parchment">{digest}</p>
          <p className="mt-2 text-sm text-mist">SHA-256 of the preimage. Not a signature, and not submitted.</p>
        </Card>
      ) : null}
    </div>
  );
}

const SCOPE_CHOICES = ["document:read", "payment:request", "agent:spawn", "agent:spend"];

export function AgentsScreen() {
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
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<string[]>(["document:read"]);
  const [uses, setUses] = useState("3");
  const [cap, setCap] = useState("0.500000");
  const [error, setError] = useState("");
  const [kind, setKind] = useState<"agent" | "contract">("agent");
  const [sponsorName, setSponsorName] = useState("");
  const [purpose, setPurpose] = useState("");
  const [sponsorCap, setSponsorCap] = useState("0.250000");
  const [sponsorError, setSponsorError] = useState("");

  const waiting = ask ? agents.find((a) => a.id === ask.agentId) : undefined;
  const verified = tier === "verified";

  return (
    <div className="space-y-6">
      <div>
        <SectionLabel>Charmed agents</SectionLabel>
        <h2 className="mt-1 font-display text-3xl text-parchment">Sponsor, then delegate</h2>
        <p className="mt-2 text-sm text-mist">
          Sponsorship needs a verified human and stamps your qcb1pq address on the agent or contract. Delegation is narrower, and it does not prove personhood.
        </p>
      </div>

      <Card>
        <SectionLabel>Sponsor desk</SectionLabel>
        {verified ? (
          <p className="mt-2 text-sm text-mist">Sponsor id {shortAddress(getAddress())}. Nothing here is deployed to the devnet.</p>
        ) : (
          <p className="mt-2 text-sm text-clay">Locked. Only a verified human can sponsor. A vendor session will not do it.</p>
        )}
        <div className="mt-4 grid grid-cols-2 gap-2">
          <button
            type="button"
            onClick={() => setKind("agent")}
            className={`h-12 rounded-xl border text-sm font-medium ${kind === "agent" ? "border-brass bg-brass text-ink" : "border-line bg-raised text-parchment"}`}
          >
            Agent
          </button>
          <button
            type="button"
            onClick={() => setKind("contract")}
            className={`h-12 rounded-xl border text-sm font-medium ${kind === "contract" ? "border-brass bg-brass text-ink" : "border-line bg-raised text-parchment"}`}
          >
            Contract
          </button>
        </div>
        <form
          className="mt-3 space-y-3"
          onSubmit={(e) => {
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
          }}
        >
          <Field label="Name">
            <input className={inputClass} value={sponsorName} onChange={(e) => setSponsorName(e.target.value)} placeholder={kind === "agent" ? "Archivist" : "Escrow terms"} disabled={!verified} />
          </Field>
          <Field label="Purpose">
            <input className={inputClass} value={purpose} onChange={(e) => setPurpose(e.target.value)} placeholder={kind === "agent" ? "Reads documents you already granted" : "Holds a job payment until both sides sign"} disabled={!verified} />
          </Field>
          {kind === "agent" ? (
            <Field label="Spend cap QCB">
              <input className={inputClass} inputMode="decimal" value={sponsorCap} onChange={(e) => setSponsorCap(e.target.value)} disabled={!verified} />
            </Field>
          ) : null}
          {sponsorError ? <p className="text-sm text-clay">{sponsorError}</p> : null}
          <PrimaryButton type="submit" disabled={!verified}>
            {kind === "agent" ? "Sponsor agent" : "Sponsor contract"}
          </PrimaryButton>
        </form>
        {sponsored.length > 0 ? (
          <ul className="mt-4 space-y-2 border-t border-line pt-3">
            {sponsored.map((item) => (
              <li key={item.id}>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-base text-parchment">{item.name}</p>
                    <p className="text-sm text-mist">
                      {item.kind === "agent" ? "Sponsored agent" : "Sponsored contract"}
                      {item.status === "revoked" ? " · revoked" : ""}
                    </p>
                  </div>
                  {item.status === "active" ? (
                    <button type="button" className="text-sm text-clay" onClick={() => revokeSponsored(item.id)}>
                      Revoke
                    </button>
                  ) : null}
                </div>
                <p className="mt-1 text-sm text-parchment">{item.purpose}</p>
                <p className="mt-1 text-sm text-mist">
                  Sponsor {shortAddress(getAddress())}
                  {item.kind === "agent" ? ` · cap ${formatQcb(item.spendCapUqcb)} QCB` : ""}
                </p>
              </li>
            ))}
          </ul>
        ) : null}
      </Card>

      {ask && waiting ? (
        <Card>
          <SectionLabel>Human gate</SectionLabel>
          <p className="mt-2 text-base text-parchment">
            {waiting.name} wants to {ask.action} {formatUqcb(ask.spendUqcb)}
          </p>
          <dl>
            <Row k="Resource" v={ask.resource} />
            <Row k="Scope" v={ask.scopes.join(", ")} />
            <Row k="Uses left" v={`${waiting.maxUses - waiting.uses} of ${waiting.maxUses}`} />
            <Row k="Cap left" v={formatUqcb(waiting.spendCapUqcb - waiting.spentUqcb)} />
          </dl>
          <div className="mt-4 grid grid-cols-2 gap-2">
            <GhostButton onClick={deny}>Deny</GhostButton>
            <PrimaryButton
              onClick={() => {
                const result = approve();
                toast(result.ok ? "Spend approved" : result.error);
              }}
            >
              Approve
            </PrimaryButton>
          </div>
        </Card>
      ) : (
        <Card>
          <p className="text-sm text-mist">No spend is waiting on you.</p>
        </Card>
      )}

      <ul className="space-y-2">
        {agents.map((a) => (
          <li key={a.id} className="rounded-2xl border border-line bg-panel p-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-base text-parchment">{a.name}</p>
                <p className="text-sm text-mist">{a.status === "revoked" ? "Revoked" : "Delegated"} · depth 1</p>
              </div>
              {a.status === "active" ? (
                <button type="button" className="text-sm text-clay" onClick={() => revoke(a.id)}>
                  Revoke
                </button>
              ) : null}
            </div>
            <p className="mt-2 text-sm text-parchment">{a.scopes.join(" · ")}</p>
            <p className="mt-1 text-sm text-mist">
              {a.uses} of {a.maxUses} uses · spent {formatQcb(a.spentUqcb)} of {formatQcb(a.spendCapUqcb)} QCB
            </p>
          </li>
        ))}
      </ul>

      <form
        className="space-y-3"
        onSubmit={(e) => {
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
        }}
      >
        <SectionLabel>New delegation</SectionLabel>
        <Field label="Name">
          <input className={inputClass} value={name} onChange={(e) => setName(e.target.value)} placeholder="Archivist" />
        </Field>
        <fieldset>
          <legend className="mb-2 text-xs font-medium tracking-wide text-mist uppercase">Scopes</legend>
          <div className="grid grid-cols-2 gap-2">
            {SCOPE_CHOICES.map((scope) => {
              const on = scopes.includes(scope);
              return (
                <button
                  key={scope}
                  type="button"
                  onClick={() =>
                    setScopes((cur) => (cur.includes(scope) ? cur.filter((s) => s !== scope) : [...cur, scope]))
                  }
                  className={`h-12 rounded-xl border px-2 text-sm ${on ? "border-brass bg-brass text-ink" : "border-line bg-raised text-parchment"}`}
                >
                  {scope}
                </button>
              );
            })}
          </div>
        </fieldset>
        <div className="grid grid-cols-2 gap-2">
          <Field label="max_uses">
            <input className={inputClass} inputMode="numeric" value={uses} onChange={(e) => setUses(e.target.value)} />
          </Field>
          <Field label="Spend cap QCB">
            <input className={inputClass} inputMode="decimal" value={cap} onChange={(e) => setCap(e.target.value)} />
          </Field>
        </div>
        {error ? <p className="text-sm text-clay">{error}</p> : null}
        <PrimaryButton type="submit">Delegate</PrimaryButton>
      </form>
    </div>
  );
}

const FILTERS: { id: "all" | SpecGroup; label: string }[] = [
  { id: "all", label: "All" },
  { id: "phone", label: "On the phone" },
  { id: "next", label: "Build next" },
  { id: "gate", label: "Not yet" },
];

export function SpecScreen({ go }: { go: (tab: Tab) => void }) {
  const rehearsed = useWallet((s) => s.rehearsed);
  const reset = useWallet((s) => s.reset);
  const [filter, setFilter] = useState<(typeof FILTERS)[number]["id"]>("all");
  const items = SPEC.filter((item) => filter === "all" || item.group === filter);

  const brief = SPEC.map((item) => `${item.group.toUpperCase()} — ${item.title}\n${item.detail}`).join("\n\n");

  return (
    <div className="space-y-6">
      <div>
        <SectionLabel>Required spec</SectionLabel>
        <h2 className="mt-1 font-display text-3xl text-parchment">What the wallet still owes</h2>
        <p className="mt-2 text-sm text-mist">
          Taken from chain-forge-engine: the Android reference client, chain-forge-wallet, and the DIS return gates. Rehearsed items are flows you have already walked here.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-2">
        {FILTERS.map((f) => (
          <button
            key={f.id}
            type="button"
            onClick={() => setFilter(f.id)}
            className={`h-12 rounded-xl border text-sm ${filter === f.id ? "border-brass bg-brass text-ink" : "border-line bg-panel text-parchment"}`}
          >
            {f.label}
          </button>
        ))}
      </div>

      <ul className="space-y-3">
        {items.map((item) => {
          const done = item.rehearsal ? rehearsed.includes(item.rehearsal) : false;
          const label = item.group === "phone" ? "On phone" : item.group === "gate" ? "Return gate" : done ? "Rehearsed" : "Needed";
          return (
            <li key={item.id} className="rounded-2xl border border-line bg-panel p-4">
              <div className="flex items-center justify-between gap-3">
                <p className="text-xs tracking-wide text-mist uppercase">{label}</p>
                {item.surface ? (
                  <button type="button" className="text-sm text-brass" onClick={() => go(item.surface!)}>
                    Open
                  </button>
                ) : null}
              </div>
              <p className="mt-1 text-base text-parchment">{item.title}</p>
              <p className="mt-1 text-sm text-mist">{item.detail}</p>
            </li>
          );
        })}
      </ul>

      <GhostButton onClick={() => void copyText(brief, "Build brief copied")}>Copy build brief</GhostButton>
      <button type="button" className="block text-sm text-mist" onClick={reset}>
        Reset rehearsal
      </button>
    </div>
  );
}
