import { useEffect, useState } from "react";
import { Toaster } from "sonner";
import { ArrowLeftRight, Bot, Fingerprint, Hexagon, ListChecks } from "lucide-react";
import type { Tab } from "@/lib/qattice";
import { keypairStatus } from "@/lib/keypair-store";
import { useWallet } from "@/lib/wallet-store";
import { AgentsScreen, HomeScreen, MoveScreen, SpecScreen, StoneScreen } from "@/components/qattice/screens";
import { InitWallet, UnlockWallet } from "@/components/qattice/init-wallet";

const NAV: { id: Tab; label: string; icon: typeof Hexagon }[] = [
  { id: "home", label: "Home", icon: Hexagon },
  { id: "stone", label: "Stone", icon: Fingerprint },
  { id: "move", label: "Move", icon: ArrowLeftRight },
  { id: "agents", label: "Agents", icon: Bot },
  { id: "spec", label: "Spec", icon: ListChecks },
];

type Phase = "loading" | "init" | "unlock" | "ready";

export function QatticeApp() {
  const tab = useWallet((s) => s.tab);
  const setTab = useWallet((s) => s.setTab);
  const [phase, setPhase] = useState<Phase>("loading");

  useEffect(() => {
    const status = keypairStatus();
    if (status === "none") {
      setPhase("init");
      return;
    }
    if (status === "locked") {
      setPhase("unlock");
      return;
    }
    void openWallet(setPhase);
  }, []);

  if (phase === "loading") {
    return <div className="lattice min-h-dvh text-mist flex items-center justify-center text-sm">Opening wallet…</div>;
  }
  if (phase === "init") {
    return <InitWallet onDone={() => void openWallet(setPhase)} />;
  }
  if (phase === "unlock") {
    return <UnlockWallet onDone={() => void openWallet(setPhase)} />;
  }

  function go(next: Tab) {
    setTab(next);
    window.scrollTo({ top: 0 });
  }

  return (
    <div className="lattice min-h-dvh text-parchment">
      <main className="mx-auto min-h-dvh w-full max-w-md px-4 pt-6 pb-28">
        {tab === "home" ? <HomeScreen go={go} /> : null}
        {tab === "stone" ? <StoneScreen /> : null}
        {tab === "move" ? <MoveScreen /> : null}
        {tab === "agents" ? <AgentsScreen /> : null}
        {tab === "spec" ? <SpecScreen go={go} /> : null}
      </main>
      <nav className="fixed inset-x-0 bottom-0 z-10">
        <div className="mx-auto grid h-16 max-w-md grid-cols-5 border-t border-line bg-ink">
          {NAV.map((item) => {
            const Icon = item.icon;
            const on = tab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => go(item.id)}
                className={`flex flex-col items-center justify-center gap-0.5 text-xs ${on ? "text-brass" : "text-mist"}`}
              >
                <Icon size={18} strokeWidth={1.75} aria-hidden />
                {item.label}
              </button>
            );
          })}
        </div>
      </nav>
      <Toaster
        theme="dark"
        position="top-center"
        toastOptions={{
          style: {
            background: "var(--color-panel)",
            color: "var(--color-parchment)",
            border: "1px solid var(--color-line)",
          },
        }}
      />
    </div>
  );
}

async function openWallet(setPhase: (phase: Phase) => void) {
  await useWallet.persist.rehydrate();
  setPhase("ready");
  void useWallet.getState().syncFromNode();
}
