import { useState } from "react";
import { Hexagon } from "lucide-react";
import { parseKeygenJson, saveKeypair, unlockKeypair } from "@/lib/keypair-store";

type Props = { onDone: () => void };

export function InitWallet({ onDone }: Props) {
  const [raw, setRaw] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function handleImport() {
    setError("");
    const parsed = parseKeygenJson(raw);
    if ("error" in parsed) {
      setError(parsed.error);
      return;
    }
    if (passphrase.length < 8) {
      setError("Choose a passphrase of at least 8 characters.");
      return;
    }
    if (passphrase !== confirm) {
      setError("Passphrases do not match.");
      return;
    }
    setBusy(true);
    try {
      await saveKeypair(parsed, passphrase);
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="lattice min-h-dvh text-parchment flex flex-col items-center justify-center px-4">
      <div className="w-full max-w-md space-y-6">
        <div className="flex flex-col items-center gap-3 text-center">
          <Hexagon size={48} strokeWidth={1} className="text-brass" />
          <h1 className="text-2xl font-semibold tracking-tight">Qattice Wallet</h1>
          <p className="text-sm text-mist">
            Paste the JSON from <code className="text-brass">{"qcb-keygen mldsa <label>"}</code>. The address is
            derived from the public key.
          </p>
        </div>

        <div className="rounded-xl border border-line bg-panel p-4 space-y-3">
          <textarea
            className="w-full h-36 rounded-lg border border-line bg-ink p-3 text-xs font-mono text-parchment resize-none focus:outline-none focus:ring-1 focus:ring-brass"
            placeholder='{"label":"phone","scheme":"mldsa65","public_key":"...","private_key":"..."}'
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
            spellCheck={false}
          />
          <input
            type="password"
            className="w-full rounded-lg border border-line bg-ink p-3 text-sm text-parchment focus:outline-none focus:ring-1 focus:ring-brass"
            placeholder="Passphrase"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            autoComplete="new-password"
          />
          <input
            type="password"
            className="w-full rounded-lg border border-line bg-ink p-3 text-sm text-parchment focus:outline-none focus:ring-1 focus:ring-brass"
            placeholder="Confirm passphrase"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="new-password"
          />
          {error && <p className="text-xs text-red-400">{error}</p>}
          <button
            type="button"
            disabled={!raw.trim() || busy}
            onClick={() => void handleImport()}
            className="w-full rounded-lg bg-brass py-3 text-sm font-semibold text-ink disabled:opacity-40"
          >
            {busy ? "Encrypting…" : "Import keypair"}
          </button>
        </div>

        <p className="text-xs text-center text-mist">
          There is no seed phrase. Losing this passphrase or this browser storage loses the account. The key is
          encrypted at rest. While the wallet is unlocked, any script on this page can still read it. This is not an
          HSM.
        </p>
      </div>
    </div>
  );
}

export function UnlockWallet({ onDone }: Props) {
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function handleUnlock() {
    setError("");
    setBusy(true);
    const result = await unlockKeypair(passphrase);
    setBusy(false);
    if (!result.ok) {
      setError(result.error);
      return;
    }
    onDone();
  }

  return (
    <div className="lattice min-h-dvh text-parchment flex flex-col items-center justify-center px-4">
      <div className="w-full max-w-md space-y-6">
        <div className="flex flex-col items-center gap-3 text-center">
          <Hexagon size={48} strokeWidth={1} className="text-brass" />
          <h1 className="text-2xl font-semibold tracking-tight">Unlock wallet</h1>
          <p className="text-sm text-mist">The chain key stays encrypted until you enter the passphrase.</p>
        </div>
        <div className="rounded-xl border border-line bg-panel p-4 space-y-3">
          <input
            type="password"
            className="w-full rounded-lg border border-line bg-ink p-3 text-sm text-parchment focus:outline-none focus:ring-1 focus:ring-brass"
            placeholder="Passphrase"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            autoComplete="current-password"
            onKeyDown={(e) => {
              if (e.key === "Enter") void handleUnlock();
            }}
          />
          {error && <p className="text-xs text-red-400">{error}</p>}
          <button
            type="button"
            disabled={!passphrase || busy}
            onClick={() => void handleUnlock()}
            className="w-full rounded-lg bg-brass py-3 text-sm font-semibold text-ink disabled:opacity-40"
          >
            {busy ? "Unlocking…" : "Unlock"}
          </button>
        </div>
      </div>
    </div>
  );
}
