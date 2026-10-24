import { useState } from "react";
import { Hexagon } from "lucide-react";
import { saveKeypair, type WalletKeypair } from "@/lib/keypair-store";

type Props = { onDone: () => void };

export function InitWallet({ onDone }: Props) {
  const [raw, setRaw] = useState("");
  const [error, setError] = useState("");

  function handleImport() {
    setError("");
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw.trim());
    } catch {
      setError("That is not valid JSON.");
      return;
    }
    if (!parsed || typeof parsed !== "object") {
      setError("Paste the full key JSON from qcb-keygen.");
      return;
    }
    const o = parsed as Record<string, unknown>;
    if (!o.address || !o.public_key || !o.private_key || o.scheme !== "mldsa65") {
      setError("Missing fields. Need: address, public_key, private_key, scheme=mldsa65.");
      return;
    }
    const kp: WalletKeypair = {
      label: typeof o.label === "string" ? o.label : "wallet",
      scheme: "mldsa65",
      address: o.address as string,
      public_key: o.public_key as string,
      private_key: o.private_key as string,
      public_key_bytes: typeof o.public_key_bytes === "number" ? o.public_key_bytes : 1952,
      private_key_bytes: typeof o.private_key_bytes === "number" ? o.private_key_bytes : 4032,
    };
    saveKeypair(kp);
    onDone();
  }

  return (
    <div className="lattice min-h-dvh text-parchment flex flex-col items-center justify-center px-4">
      <div className="w-full max-w-md space-y-6">
        <div className="flex flex-col items-center gap-3 text-center">
          <Hexagon size={48} strokeWidth={1} className="text-brass" />
          <h1 className="text-2xl font-semibold tracking-tight">Qattice Wallet</h1>
          <p className="text-sm text-mist">
            This device needs an ML-DSA-65 keypair. Paste the JSON from{" "}
            <code className="text-brass">qcb-keygen mldsa &lt;label&gt;</code>.
          </p>
        </div>

        <div className="rounded-xl border border-line bg-panel p-4 space-y-3">
          <p className="text-xs text-mist font-mono">
            Run on your laptop:
          </p>
          <pre className="text-xs text-brass font-mono bg-ink rounded p-3 overflow-x-auto whitespace-pre-wrap break-all">
{`./target/debug/qcb-keygen mldsa <device-name>`}
          </pre>
          <p className="text-xs text-mist">
            Then paste the output below.
          </p>
          <textarea
            className="w-full h-40 rounded-lg border border-line bg-ink p-3 text-xs font-mono text-parchment resize-none focus:outline-none focus:ring-1 focus:ring-brass"
            placeholder='{"label":"phone","scheme":"mldsa65","address":"qcb1pq...","public_key":"...","private_key":"..."}'
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
            spellCheck={false}
          />
          {error && <p className="text-xs text-red-400">{error}</p>}
          <button
            type="button"
            disabled={!raw.trim()}
            onClick={handleImport}
            className="w-full rounded-lg bg-brass py-3 text-sm font-semibold text-ink disabled:opacity-40"
          >
            Import Keypair
          </button>
        </div>

        <p className="text-xs text-center text-mist">
          Your private key is stored only in this device&apos;s browser storage and never sent to any server.
        </p>
      </div>
    </div>
  );
}
