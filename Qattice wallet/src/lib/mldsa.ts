// Detached ML-DSA signatures the node will actually verify.
//
// chain-forge-crypto links pqcrypto-dilithium 0.5 `dilithium3` (PQClean).
// That build uses ML-DSA-65 sizes (1952 / 4032 / 3309) but the round-3
// message binding mu = SHAKE256(tr || msg), not FIPS 204's context prefix.
// @noble/post-quantum ml_dsa65 verifies its own signatures and rejects
// pqcrypto's. This module is a WASM build of those same C sources.

const SIG_BYTES = 3309;
const SK_BYTES = 4032;

type WasmExports = {
  memory: WebAssembly.Memory;
  _initialize: () => void;
  qcb_sign: (sig: number, siglen: number, msg: number, mlen: number, sk: number) => number;
  qcb_malloc: (n: number) => number;
  qcb_free: (p: number) => void;
};

let ready: Promise<WasmExports> | null = null;

function loadWasm(): Promise<WasmExports> {
  if (!ready) {
    ready = (async () => {
      const url = new URL("./dilithium3.wasm", import.meta.url);
      const res = await fetch(url);
      if (!res.ok) throw new Error(`Could not load dilithium3.wasm (${res.status}).`);
      const { instance } = await WebAssembly.instantiate(await res.arrayBuffer(), {
        wasi_snapshot_preview1: {
          proc_exit(code: number) {
            throw new Error(`dilithium wasm exited ${code}`);
          },
        },
      });
      const exp = instance.exports as unknown as WasmExports;
      exp._initialize();
      return exp;
    })();
  }
  return ready;
}

/** Sign `message` with a 4032-byte pqcrypto-dilithium secret key. Returns 3309 bytes. */
export async function mldsaSign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
  if (secretKey.length !== SK_BYTES) {
    throw new Error(`ML-DSA secret key must be ${SK_BYTES} bytes, got ${secretKey.length}.`);
  }
  const exp = await loadWasm();
  const alloc = (n: number) => {
    const p = exp.qcb_malloc(n);
    if (p === 0) throw new Error("dilithium wasm is out of memory.");
    return p;
  };
  const pSk = alloc(secretKey.length);
  const pMsg = alloc(message.length || 1);
  const pSig = alloc(SIG_BYTES);
  const pLen = alloc(4);
  const mem = new Uint8Array(exp.memory.buffer);
  mem.set(secretKey, pSk);
  if (message.length) mem.set(message, pMsg);
  const rc = exp.qcb_sign(pSig, pLen, pMsg, message.length, pSk);
  const slen = new DataView(exp.memory.buffer).getUint32(pLen, true);
  const sig = new Uint8Array(exp.memory.buffer).slice(pSig, pSig + slen);
  exp.qcb_free(pSk);
  exp.qcb_free(pMsg);
  exp.qcb_free(pSig);
  exp.qcb_free(pLen);
  if (rc !== 0 || sig.length !== SIG_BYTES) {
    throw new Error(`ML-DSA sign failed (status ${rc}, ${sig.length} bytes).`);
  }
  return sig;
}
