import time, statistics
from pqcrypto.sign import ml_dsa_65 as D
pk, sk = D.keygen()
msg = b"block-header-benchmark"
sig = D.sign(sk, msg)
D.verify(pk, msg, sig)  # returns None on success, raises on failure
try:
    D.verify(pk, msg + b"x", sig); print("ERROR: bad verify accepted")
except Exception as e:
    print("negative check ok:", type(e).__name__)
print(f"pk_bytes={len(pk)} sig_bytes={len(sig)}")
N = 500
s_t, v_t = [], []
for _ in range(N):
    t0 = time.perf_counter(); sig = D.sign(sk, msg); s_t.append(time.perf_counter()-t0)
for _ in range(N):
    t0 = time.perf_counter(); D.verify(pk, msg, sig); v_t.append(time.perf_counter()-t0)
s_t.sort(); v_t.sort()
print(f"sign_us median={statistics.median(s_t)*1e6:.0f} p95={s_t[int(N*.95)]*1e6:.0f}")
print(f"verify_us median={statistics.median(v_t)*1e6:.0f} p95={v_t[int(N*.95)]*1e6:.0f}")
vm = statistics.median(v_t)
for C in (32, 128, 256, 512):
    print(f"C={C}: cert_bytes={C*len(sig)} (~{C*len(sig)/1024:.0f} KiB), serial_verify_ms={C*vm*1000:.1f}")
