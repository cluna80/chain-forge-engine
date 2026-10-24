import { type ReactNode } from "react";
import { toast } from "sonner";

export function Mark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden>
      <path
        d="M4 16h8M20 16h8M16 4v8M16 20v8M9 9l5 5M18 18l5 5M23 9l-5 5M14 18l-5 5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.4"
      />
      <circle cx="16" cy="16" r="2.1" fill="currentColor" />
    </svg>
  );
}

export function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <p className="text-xs font-medium tracking-widest text-mist uppercase">{children}</p>
  );
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-2xl border border-line bg-panel p-4 ${className}`}>{children}</section>
  );
}

export function Field({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-xs font-medium tracking-wide text-mist uppercase">{label}</span>
      {children}
    </label>
  );
}

export const inputClass =
  "h-12 w-full rounded-xl border border-line bg-raised px-3 text-base text-parchment outline-none placeholder:text-mist/70 focus:border-brass disabled:opacity-40";

export function PrimaryButton({
  children,
  onClick,
  disabled,
  type = "button",
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  type?: "button" | "submit";
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className="h-12 w-full rounded-xl bg-brass px-4 text-base font-medium text-ink transition-opacity disabled:opacity-40"
    >
      {children}
    </button>
  );
}

export function GhostButton({
  children,
  onClick,
  disabled,
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="h-12 w-full rounded-xl border border-line bg-raised px-4 text-sm font-medium text-parchment disabled:opacity-40"
    >
      {children}
    </button>
  );
}

export async function copyText(value: string, label: string) {
  try {
    await navigator.clipboard.writeText(value);
    toast(label);
  } catch {
    toast("Copy is blocked in this browser");
  }
}

export function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-line/80 py-2 last:border-0">
      <dt className="text-sm text-mist">{k}</dt>
      <dd className="max-w-[16rem] text-right font-mono text-sm break-all text-parchment">{v}</dd>
    </div>
  );
}
