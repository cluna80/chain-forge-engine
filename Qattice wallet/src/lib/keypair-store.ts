// Wallet keypair — stored in localStorage per device.
// Each device pastes its own qcb-keygen output here on first launch.

export type WalletKeypair = {
  label: string;
  scheme: "mldsa65";
  address: string;
  public_key: string;
  private_key: string;
  public_key_bytes: number;
  private_key_bytes: number;
};

const STORAGE_KEY = "qattice_wallet_keypair";

export function loadKeypair(): WalletKeypair | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as WalletKeypair;
    if (!parsed.address || !parsed.scheme) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function saveKeypair(kp: WalletKeypair): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(kp));
}

export function clearKeypair(): void {
  localStorage.removeItem(STORAGE_KEY);
}

export function getAddress(): string {
  try {
    const kp = loadKeypair();
    return kp?.address ?? "qcb1pq1k4rm7w4llet9h0lder2charm";
  } catch {
    return "qcb1pq1k4rm7w4llet9h0lder2charm";
  }
}
