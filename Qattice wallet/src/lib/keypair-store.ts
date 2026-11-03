// Chain account key. The secret is encrypted at rest (PBKDF2-SHA256 + AES-GCM).
// It is decrypted only into memory for signing. There is no seed phrase:
// losing the passphrase or this browser storage loses the account.
// A legacy plaintext record (v1) still loads so an already-imported key is not stranded.

import { sha3_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

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
const PBKDF2_ITERATIONS = 210_000;
const PK_BYTES = 1952;
const SK_BYTES = 4032;

type PublicFields = {
  label: string;
  scheme: "mldsa65";
  address: string;
  public_key: string;
  public_key_bytes: number;
  private_key_bytes: number;
};

type V2Record = PublicFields & {
  v: 2;
  kdf: "PBKDF2-SHA256";
  iterations: number;
  salt: string;
  iv: string;
  ciphertext: string;
};

type V1Record = PublicFields & {
  v?: 1;
  private_key: string;
};

type Stored = V2Record | V1Record;

let memory: WalletKeypair | null = null;

export function addressFromPublicKey(publicKeyHex: string): string {
  const hash = sha3_256(hexToBytes(publicKeyHex));
  return `qcb1pq${bytesToHex(hash.slice(0, 20))}`;
}

function isHex(value: string, bytes: number) {
  return value.length === bytes * 2 && /^[0-9a-fA-F]+$/.test(value);
}

export function parseKeygenJson(raw: string): WalletKeypair | { error: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.trim());
  } catch {
    return { error: "That is not valid JSON." };
  }
  if (!parsed || typeof parsed !== "object") return { error: "Paste the full key JSON from qcb-keygen." };
  const o = parsed as Record<string, unknown>;
  if (o.scheme !== "mldsa65" || typeof o.public_key !== "string" || typeof o.private_key !== "string") {
    return { error: "Need public_key, private_key, and scheme mldsa65." };
  }
  const public_key = o.public_key.toLowerCase();
  const private_key = o.private_key.toLowerCase();
  if (!isHex(public_key, PK_BYTES)) return { error: `public_key must be ${PK_BYTES} bytes of hex.` };
  if (!isHex(private_key, SK_BYTES)) return { error: `private_key must be ${SK_BYTES} bytes of hex.` };
  const derived = addressFromPublicKey(public_key);
  if (typeof o.address === "string" && o.address && o.address !== derived) {
    return { error: `Address does not match this public key. Expected ${derived}.` };
  }
  return {
    label: typeof o.label === "string" ? o.label : "wallet",
    scheme: "mldsa65",
    address: derived,
    public_key,
    private_key,
    public_key_bytes: PK_BYTES,
    private_key_bytes: SK_BYTES,
  };
}

function readStored(): Stored | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Stored;
    if (!parsed || parsed.scheme !== "mldsa65" || !parsed.address || !parsed.public_key) return null;
    return parsed;
  } catch {
    return null;
  }
}

function toKeypair(rec: PublicFields, private_key: string): WalletKeypair {
  return {
    label: rec.label,
    scheme: "mldsa65",
    address: rec.address,
    public_key: rec.public_key,
    private_key,
    public_key_bytes: rec.public_key_bytes || PK_BYTES,
    private_key_bytes: rec.private_key_bytes || SK_BYTES,
  };
}

function copyBuf(bytes: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(out).set(bytes);
  return out;
}

async function aesKey(passphrase: string, salt: Uint8Array, iterations: number) {
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: copyBuf(salt), iterations, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function saveKeypair(kp: WalletKeypair, passphrase: string): Promise<void> {
  if (passphrase.length < 8) throw new Error("Passphrase must be at least 8 characters.");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await aesKey(passphrase, salt, PBKDF2_ITERATIONS);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: copyBuf(iv) },
    key,
    new TextEncoder().encode(kp.private_key),
  );
  const rec: V2Record = {
    v: 2,
    kdf: "PBKDF2-SHA256",
    iterations: PBKDF2_ITERATIONS,
    salt: bytesToHex(salt),
    iv: bytesToHex(iv),
    ciphertext: bytesToHex(new Uint8Array(ciphertext)),
    label: kp.label,
    scheme: "mldsa65",
    address: kp.address,
    public_key: kp.public_key,
    public_key_bytes: kp.public_key_bytes,
    private_key_bytes: kp.private_key_bytes,
  };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(rec));
  memory = kp;
}

export async function unlockKeypair(passphrase: string): Promise<{ ok: true } | { ok: false; error: string }> {
  const rec = readStored();
  if (!rec) return { ok: false, error: "No key on this device." };
  if (!("ciphertext" in rec)) {
    if ("private_key" in rec && rec.private_key) {
      memory = toKeypair(rec, rec.private_key);
      return { ok: true };
    }
    return { ok: false, error: "Stored key is unreadable." };
  }
  try {
    const key = await aesKey(passphrase, hexToBytes(rec.salt), rec.iterations || PBKDF2_ITERATIONS);
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: copyBuf(hexToBytes(rec.iv)) },
      key,
      copyBuf(hexToBytes(rec.ciphertext)),
    );
    const private_key = new TextDecoder().decode(plain);
    if (!isHex(private_key, SK_BYTES)) return { ok: false, error: "Decrypted key is not an ML-DSA secret." };
    memory = toKeypair(rec, private_key);
    return { ok: true };
  } catch {
    return { ok: false, error: "Wrong passphrase." };
  }
}

export function lockKeypair(): void {
  memory = null;
}

export function clearKeypair(): void {
  memory = null;
  localStorage.removeItem(STORAGE_KEY);
}

/** "plaintext" is a legacy v1 record. New imports are "passphrase". */
export function keyStorageKind(): "none" | "passphrase" | "plaintext" {
  const rec = readStored();
  if (!rec) return "none";
  return "ciphertext" in rec ? "passphrase" : "plaintext";
}

export function keypairStatus(): "none" | "locked" | "unlocked" {
  const rec = readStored();
  if (!rec) return "none";
  if (memory?.address === rec.address) return "unlocked";
  if (!("ciphertext" in rec) && "private_key" in rec && rec.private_key) {
    memory = toKeypair(rec, rec.private_key);
    return "unlocked";
  }
  return "locked";
}

export function getUnlocked(): WalletKeypair | null {
  const rec = readStored();
  if (!rec) return null;
  if (memory?.address === rec.address) return memory;
  if (!("ciphertext" in rec) && "private_key" in rec && rec.private_key) {
    memory = toKeypair(rec, rec.private_key);
    return memory;
  }
  return null;
}

export function getAddress(): string {
  const rec = readStored();
  if (rec?.address) return rec.address;
  return memory?.address ?? "qcb1pq1k4rm7w4llet9h0lder2charm";
}
