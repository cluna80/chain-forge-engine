import time, statistics
from dilithium_py.ml_dsa import ML_DSA_65 as D
pk, sk = D.keygen()
msg = b"block-header-benchmark"
sig = D.sign(sk, msg)
print(f"pk_bytes={len(pk)} sig_bytes={len(sig)}")
N = 20
t = []
for _ in range(N):
    s0 = time.perf_counter(); D.sign(sk, msg); t.append(time.perf_counter()-s0)
print(f"sign_ms median={statistics.median(t)*1000:.1f}")
v = []
for _ in range(N):
    s0 = time.perf_counter(); ok = D.verify(pk, msg, sig); v.append(time.perf_counter()-s0)
print(f"verify_ms median={statistics.median(v)*1000:.1f} ok={ok}")
for C in (128, 256, 512):
    print(f"C={C}: naive_cert_bytes={C*len(sig)} (~{C*len(sig)/1024:.0f} KiB), naive_verify_ms={C*statistics.median(v)*1000:.0f}")
