#!/usr/bin/env python3
"""
CIRFI Economic Model v0.1 — Stress-Test Simulation
====================================================
Tests the 12 stress scenarios from the formal model doc against
a range of open parameters, printing summary tables to stdout.

Model recap:
  Two MINT paths (independent, no conversion between them):
    1) QCB burn:       dS_burn(t) = Q(t) * R(t)
    2) Contribution:   dS_earn(t) = sum_i E(i,t)  (VCA-measured)

  BURN (consumption):
    - split:  p_prov * C(t) → provider rewards (already counted in earning)
              p_burn * C(t) → permanent burn
              p_res  * C(t) → protocol reserve
    - net supply change: dS(t) = dS_burn + dS_earn - p_burn*C(t) - p_res*C(t)

  Conversion rate (QCB→CIRFI):
    U_bar(r,t) = alpha*U(r,t) + (1-alpha)*U_bar(r,t-1)   [EMA]
    Rt(r,t)    = R0(r) * (U_star / U_bar(r,t)) ^ gamma
    Rt clamped to [Rmin, Rmax]

  Per-resource congestion multiplier (for provider earning):
    M(r,t) = 1 + beta*(U_bar(r,t) - U_star)   [linear; clamp >=0]

  Provider earning:
    E(i,t) = sum_r  w(r) * C(i,r,t) * BaseRate(r) * M(r,t)

Resources modeled:
    compute, storage, zk, oracle, ai, bandwidth
"""

from __future__ import annotations
import math
import random
from dataclasses import dataclass, field
from typing import Dict, List, Tuple
import sys

# ─────────────────────────────────────────────────────────────────────────────
# Parameter sets to sweep
# ─────────────────────────────────────────────────────────────────────────────

RESOURCES = ["compute", "storage", "zk", "oracle", "ai", "bandwidth"]

@dataclass
class Params:
    # EMA smoothing
    alpha: float = 0.10

    # Conversion rate formula
    gamma: float = 1.5
    U_star: float = 0.70
    Rmin: float = 0.5        # floor: 0.5 CIRFI per QCB
    Rmax: float = 5.0        # ceiling: 5.0 CIRFI per QCB
    # R0 per resource (base CIRFI per QCB at U = U_star)
    R0: Dict[str, float] = field(default_factory=lambda: {
        "compute": 1.0, "storage": 0.8, "zk": 2.0,
        "oracle": 1.2, "ai": 1.5, "bandwidth": 0.6,
    })

    # Congestion multiplier slope
    beta: float = 1.0        # M = 1 + beta*(U_bar - U_star)

    # Provider earning: resource weights (sum to 1)
    w: Dict[str, float] = field(default_factory=lambda: {
        "compute": 0.30, "storage": 0.20, "zk": 0.20,
        "oracle": 0.10, "ai": 0.15, "bandwidth": 0.05,
    })

    # BaseRate per resource (CIRFI per unit consumed per tick)
    BaseRate: Dict[str, float] = field(default_factory=lambda: {
        "compute": 0.001, "storage": 0.0005, "zk": 0.005,
        "oracle": 0.002, "ai": 0.003, "bandwidth": 0.0002,
    })

    # Consumption split (must sum to 1)
    p_prov: float = 0.60   # → provider rewards
    p_burn: float = 0.25   # → permanent burn
    p_res:  float = 0.15   # → protocol reserve

    # Network scale
    n_providers: int = 100
    n_users: int = 1000

    # Simulation ticks
    T: int = 200

    # Initial supply
    S0: float = 1_000_000.0

    def __post_init__(self):
        assert abs(self.p_prov + self.p_burn + self.p_res - 1.0) < 1e-9, \
            "consumption split must sum to 1"
        assert abs(sum(self.w.values()) - 1.0) < 1e-9, \
            f"w must sum to 1, got {sum(self.w.values())}"


# ─────────────────────────────────────────────────────────────────────────────
# Simulation core
# ─────────────────────────────────────────────────────────────────────────────

def clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def run_scenario(
    p: Params,
    utilization_fn,      # fn(r: str, t: int) -> float  [0,1]
    qcb_burn_fn,         # fn(t: int) -> float  (total QCB burned that tick)
    scenario_name: str = "?",
    verbose: bool = False,
) -> dict:
    """
    Simulate T ticks.  Returns summary statistics.

    utilization_fn(r, t) → U(r, t) ∈ [0,1]
    qcb_burn_fn(t)        → Q(t) ≥ 0 (total QCB burned across all users)
    """
    # State
    S = p.S0
    U_bar: Dict[str, float] = {r: p.U_star for r in RESOURCES}

    history = []

    for t in range(p.T):
        # 1) Update EMA utilization per resource
        for r in RESOURCES:
            U_t = utilization_fn(r, t)
            U_bar[r] = p.alpha * U_t + (1 - p.alpha) * U_bar[r]
            U_bar[r] = clamp(U_bar[r], 0.0, 1.0)

        # 2) Compute per-resource conversion rate  Rt(r)
        Rt: Dict[str, float] = {}
        for r in RESOURCES:
            ub = max(U_bar[r], 1e-6)   # avoid div-by-zero
            rt = p.R0[r] * (p.U_star / ub) ** p.gamma
            Rt[r] = clamp(rt, p.Rmin, p.Rmax)

        # Blended rate (weighted by w) for QCB burn path
        Rt_blend = sum(p.w[r] * Rt[r] for r in RESOURCES)

        # 3) QCB burn mint
        Q_t = qcb_burn_fn(t)
        dS_burn = Q_t * Rt_blend

        # 4) Provider earning (contribution path)
        #    Assume total network consumption C_total = sum of all user activity
        #    Distributed uniformly across providers for simplicity
        M: Dict[str, float] = {}
        for r in RESOURCES:
            M[r] = max(0.0, 1.0 + p.beta * (U_bar[r] - p.U_star))

        # Total CIRFI earned = sum_r w(r)*C_total(r)*BaseRate(r)*M(r)
        # C_total(r) = utilization * some capacity proxy
        capacity = p.n_users * 10.0   # arbitrary units; consistent baseline
        dS_earn = 0.0
        for r in RESOURCES:
            C_r = utilization_fn(r, t) * capacity
            dS_earn += p.w[r] * C_r * p.BaseRate[r] * M[r]

        # 5) Consumption (CIRFI spent to use the network)
        #    Total CIRFI consumed ≈ what was earned (users pay what providers earn)
        #    Use the same calculation, un-multiplied by congestion for user side
        C_total_cirfi = 0.0
        for r in RESOURCES:
            C_r = utilization_fn(r, t) * capacity
            C_total_cirfi += p.w[r] * C_r * p.BaseRate[r]

        # 6) Burns and reserves from consumption
        dS_permanent_burn = p.p_burn * C_total_cirfi
        dS_reserve        = p.p_res  * C_total_cirfi

        # 7) Net supply change
        #    + dS_burn (QCB path mint)
        #    + dS_earn (contribution path mint)
        #    - dS_permanent_burn (consumption split: burned)
        #    - dS_reserve (consumption split: reserve, out of circulating)
        #    Provider portion p_prov is NOT re-minted; it redistributes from
        #    the consumption pool — already accounted as dS_earn from contributing.
        #    (This is a simplification: we treat earn ≈ p_prov*C for flow balance)
        dS = dS_burn + dS_earn - dS_permanent_burn - dS_reserve
        S = max(0.0, S + dS)

        history.append({
            "t": t,
            "S": S,
            "dS": dS,
            "dS_burn": dS_burn,
            "dS_earn": dS_earn,
            "dS_perm_burn": dS_permanent_burn,
            "Rt_blend": Rt_blend,
            "U_bar": dict(U_bar),
            "Q_t": Q_t,
        })

        if verbose and t % 20 == 0:
            print(f"  t={t:3d}  S={S:12,.0f}  dS={dS:+9,.0f}  "
                  f"Rt={Rt_blend:.3f}  Q={Q_t:.0f}  earn={dS_earn:.0f}  "
                  f"burn={dS_permanent_burn:.0f}")

    S_final = history[-1]["S"]
    S_min   = min(h["S"] for h in history)
    S_max   = max(h["S"] for h in history)
    dS_vals = [h["dS"] for h in history]
    inflate_ticks = sum(1 for d in dS_vals if d > 0)
    deflate_ticks = sum(1 for d in dS_vals if d < 0)

    # Equilibrium detection: last 20 ticks
    tail = history[-20:]
    tail_dS = [h["dS"] for h in tail]
    tail_mean = sum(tail_dS) / len(tail_dS)
    tail_range = max(tail_dS) - min(tail_dS)
    stable = abs(tail_mean) < 0.01 * p.S0 and tail_range < 0.05 * p.S0

    return {
        "scenario": scenario_name,
        "S_init": p.S0,
        "S_final": S_final,
        "S_min": S_min,
        "S_max": S_max,
        "inflate_ticks": inflate_ticks,
        "deflate_ticks": deflate_ticks,
        "equilibrium": stable,
        "tail_mean_dS": tail_mean,
        "history": history,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Scenario definitions (the 12 from the model doc + 3 extras)
# ─────────────────────────────────────────────────────────────────────────────

def make_scenarios(p: Params):
    """Return list of (name, utilization_fn, qcb_burn_fn) tuples."""

    # Helpers
    def const_util(v: float):
        return lambda r, t: v

    def ramp_util(start: float, end: float):
        return lambda r, t: start + (end - start) * t / max(p.T - 1, 1)

    def spike_util(base: float, spike_start: int, spike_end: int, spike_val: float):
        def f(r, t):
            if spike_start <= t < spike_end:
                return spike_val
            return base
        return f

    def const_qcb(v: float):
        return lambda t: v

    def step_qcb(v_before: float, v_after: float, step_t: int):
        return lambda t: v_after if t >= step_t else v_before

    def zero_qcb():
        return lambda t: 0.0

    def ramp_qcb(start: float, end: float):
        return lambda t: start + (end - start) * t / max(p.T - 1, 1)

    scenarios = [
        # ── 1. Steady-state nominal ──────────────────────────────────────────
        (
            "1. Steady-state nominal (U=0.70, moderate QCB)",
            const_util(0.70),
            const_qcb(500.0),
        ),
        # ── 2. Low utilization (U→0.20) ─────────────────────────────────────
        (
            "2. Low utilization (U=0.20, normal QCB demand)",
            const_util(0.20),
            const_qcb(500.0),
        ),
        # ── 3. Network saturation (U→0.95) ──────────────────────────────────
        (
            "3. Network saturation (U=0.95, surge QCB demand)",
            const_util(0.95),
            const_qcb(2000.0),
        ),
        # ── 4. QCB burn drought ──────────────────────────────────────────────
        (
            "4. QCB burn drought (zero QCB, earn-only)",
            const_util(0.60),
            zero_qcb(),
        ),
        # ── 5. Contribution earn collapse ────────────────────────────────────
        (
            "5. Earn collapse (U≈0, QCB only — no providers active)",
            const_util(0.01),
            const_qcb(500.0),
        ),
        # ── 6. CIRFI hoarding (no consumption spend) ─────────────────────────
        # Model approximation: set p_prov=1, p_burn=0, p_res=0 (users earn but don't spend)
        # We simulate by zeroing out consumption burn
        (
            "6. No consumption burn (users hoard, never spend CIRFI)",
            const_util(0.70),
            const_qcb(500.0),
        ),
        # ── 7. Congestion spike & recovery ───────────────────────────────────
        (
            "7. Congestion spike t=50..70 (U→0.99) then recovery",
            spike_util(0.60, 50, 70, 0.99),
            const_qcb(500.0),
        ),
        # ── 8. Gradual network growth ────────────────────────────────────────
        (
            "8. Gradual growth (U: 0.20→0.80, QCB: 100→1000)",
            ramp_util(0.20, 0.80),
            ramp_qcb(100.0, 1000.0),
        ),
        # ── 9. Rapid deflation attack ────────────────────────────────────────
        # Attacker burns huge QCB to mint CIRFI, then all consumption stops
        (
            "9. Rapid deflation: burn-surge then consumption collapse",
            lambda r, t: 0.70 if t < 20 else 0.0,
            step_qcb(5000.0, 0.0, 20),
        ),
        # ── 10. Gamma sensitivity — low γ (near-linear) ──────────────────────
        (
            "10. Low gamma (γ=0.5, weak congestion response)",
            const_util(0.90),
            const_qcb(500.0),
        ),
        # ── 11. Reserve accumulation check ───────────────────────────────────
        (
            "11. Reserve check (high-volume nominal, p_res=0.15)",
            const_util(0.70),
            const_qcb(1000.0),
        ),
        # ── 12. Cross-resource imbalance ─────────────────────────────────────
        # ZK and AI saturated; compute/storage idle
        (
            "12. Resource imbalance (ZK+AI at 0.95, rest at 0.20)",
            lambda r, t: 0.95 if r in ("zk", "ai") else 0.20,
            const_qcb(500.0),
        ),
        # ── 13. (extra) Extreme Rmax test ────────────────────────────────────
        (
            "13. Extreme Rmax hit (U→0.01, rate clamped at Rmax=5)",
            const_util(0.01),
            const_qcb(5000.0),
        ),
        # ── 14. (extra) Alpha sensitivity (fast EMA) ─────────────────────────
        (
            "14. Fast EMA (alpha=0.50) spike recovery",
            spike_util(0.60, 50, 70, 0.99),
            const_qcb(500.0),
        ),
        # ── 15. (extra) Alpha sensitivity (slow EMA) ─────────────────────────
        (
            "15. Slow EMA (alpha=0.02) spike recovery",
            spike_util(0.60, 50, 70, 0.99),
            const_qcb(500.0),
        ),
    ]
    return scenarios


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 6 needs a modified params copy (no burn from consumption)
# Scenarios 10, 14, 15 need modified gamma / alpha
# ─────────────────────────────────────────────────────────────────────────────

def run_all(base_params: Params, verbose: bool = False) -> List[dict]:
    scenarios = make_scenarios(base_params)
    results = []

    for i, (name, u_fn, q_fn) in enumerate(scenarios):
        # Build per-scenario param overrides
        p = Params(
            alpha=base_params.alpha,
            gamma=base_params.gamma,
            U_star=base_params.U_star,
            Rmin=base_params.Rmin,
            Rmax=base_params.Rmax,
            R0=dict(base_params.R0),
            beta=base_params.beta,
            w=dict(base_params.w),
            BaseRate=dict(base_params.BaseRate),
            p_prov=base_params.p_prov,
            p_burn=base_params.p_burn,
            p_res=base_params.p_res,
            n_providers=base_params.n_providers,
            n_users=base_params.n_users,
            T=base_params.T,
            S0=base_params.S0,
        )

        if i == 5:  # scenario 6: no consumption burn
            p.p_burn = 0.0
            p.p_res  = 0.0
            p.p_prov = 1.0

        if i == 9:  # scenario 10: low gamma
            p.gamma = 0.5

        if i == 13:  # scenario 14: fast EMA
            p.alpha = 0.50

        if i == 14:  # scenario 15: slow EMA
            p.alpha = 0.02

        if verbose:
            print(f"\n{'─'*70}")
            print(f"Running: {name}")
            print(f"{'─'*70}")

        r = run_scenario(p, u_fn, q_fn, scenario_name=name, verbose=verbose)
        results.append(r)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Gamma parameter sweep
# ─────────────────────────────────────────────────────────────────────────────

def gamma_sweep(verbose: bool = False) -> List[dict]:
    """Run scenario 3 (saturation) and scenario 2 (low-util) across γ values."""
    gammas = [0.5, 1.0, 1.5, 2.0, 3.0]
    results = []
    base = Params()

    for g in gammas:
        p = Params(gamma=g)

        # Saturation
        u_fn = lambda r, t: 0.95
        q_fn = lambda t: 2000.0
        r = run_scenario(p, u_fn, q_fn, scenario_name=f"Sat γ={g}", verbose=False)
        r["gamma"] = g
        r["scenario_type"] = "saturation"
        results.append(r)

        # Low util
        u_fn2 = lambda r, t: 0.20
        q_fn2 = lambda t: 500.0
        r2 = run_scenario(p, u_fn2, q_fn2, scenario_name=f"LowU γ={g}", verbose=False)
        r2["gamma"] = g
        r2["scenario_type"] = "low_util"
        results.append(r2)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────

def pct_change(s_init: float, s_final: float) -> str:
    if s_init == 0:
        return "∞"
    pct = (s_final - s_init) / s_init * 100
    return f"{pct:+.1f}%"


def print_summary_table(results: List[dict], title: str = "Results"):
    col_w = [60, 12, 12, 9, 8, 10]
    hdr = ["Scenario", "S_final", "S_max", "Δ%", "Eq?", "tail_dS/S"]
    sep = "─" * (sum(col_w) + len(col_w) * 3)

    print(f"\n{'═'*len(sep)}")
    print(f"  {title}")
    print(f"{'═'*len(sep)}")
    print(f"  {hdr[0]:<{col_w[0]}}  {hdr[1]:>{col_w[1]}}  "
          f"{hdr[2]:>{col_w[2]}}  {hdr[3]:>{col_w[3]}}  "
          f"{hdr[4]:>{col_w[4]}}  {hdr[5]:>{col_w[5]}}")
    print(f"  {sep}")

    for r in results:
        name   = r["scenario"][:col_w[0]]
        sfinal = f"{r['S_final']:,.0f}"
        smax   = f"{r['S_max']:,.0f}"
        dp     = pct_change(r["S_init"], r["S_final"])
        eq     = "✓" if r["equilibrium"] else "✗"
        # tail_mean as fraction of S0
        ts = r["tail_mean_dS"] / r["S_init"] * 100
        ts_str = f"{ts:+.3f}%"
        print(f"  {name:<{col_w[0]}}  {sfinal:>{col_w[1]}}  "
              f"{smax:>{col_w[2]}}  {dp:>{col_w[3]}}  "
              f"{eq:>{col_w[4]}}  {ts_str:>{col_w[5]}}")

    print(f"  {sep}")
    print(f"  S0 = {results[0]['S_init']:,.0f} for all scenarios above")


def print_gamma_sweep(results: List[dict]):
    print(f"\n{'═'*80}")
    print("  Gamma (γ) Parameter Sweep")
    print(f"{'═'*80}")
    print(f"  {'γ':>5}  {'Scenario':>12}  {'S_final':>14}  {'Δ%':>9}  "
          f"{'S_max':>14}  {'Eq?':>4}")
    print(f"  {'─'*70}")
    for r in sorted(results, key=lambda x: (x["gamma"], x["scenario_type"])):
        dp = pct_change(r["S_init"], r["S_final"])
        eq = "✓" if r["equilibrium"] else "✗"
        print(f"  {r['gamma']:>5.1f}  {r['scenario_type']:>12}  "
              f"{r['S_final']:>14,.0f}  {dp:>9}  "
              f"{r['S_max']:>14,.0f}  {eq:>4}")


def print_parameter_table():
    p = Params()
    print(f"\n{'═'*60}")
    print("  Default Parameter Set")
    print(f"{'═'*60}")
    print(f"  alpha (EMA)       : {p.alpha}")
    print(f"  gamma (rate curve): {p.gamma}")
    print(f"  U_star (target U) : {p.U_star}")
    print(f"  Rmin, Rmax        : {p.Rmin}, {p.Rmax}")
    print(f"  beta (cong slope) : {p.beta}")
    print(f"  p_prov / p_burn / p_res: {p.p_prov} / {p.p_burn} / {p.p_res}")
    print(f"  T (ticks)         : {p.T}")
    print(f"  S0                : {p.S0:,.0f}")
    print(f"\n  R0 (base conversion rate per resource):")
    for r, v in p.R0.items():
        print(f"    {r:<12}: {v}")
    print(f"\n  w (resource weights):")
    for r, v in p.w.items():
        print(f"    {r:<12}: {v}")
    print(f"\n  BaseRate (CIRFI per unit per tick):")
    for r, v in p.BaseRate.items():
        print(f"    {r:<12}: {v}")


def print_risk_flags(results: List[dict]):
    print(f"\n{'═'*70}")
    print("  Risk Flags")
    print(f"{'═'*70}")
    flags = []

    for r in results:
        name = r["scenario"]
        s0 = r["S_init"]
        sf = r["S_final"]
        sm = r["S_max"]
        change = (sf - s0) / s0

        if change > 5.0:
            flags.append((name, f"HYPERINFLATION: supply grew {change*100:.0f}%"))
        elif change < -0.90:
            flags.append((name, f"COLLAPSE: supply fell {abs(change)*100:.0f}%"))

        if sm / s0 > 50:
            flags.append((name, f"PEAK RUNAWAY: S_max/S0 = {sm/s0:.0f}x"))

        if not r["equilibrium"] and abs(r["tail_mean_dS"] / s0) > 0.005:
            td = r["tail_mean_dS"] / s0 * 100
            flags.append((name, f"NO EQUILIBRIUM: tail drift = {td:+.3f}%/tick"))

    if not flags:
        print("  ✓ No risk flags raised across all scenarios.")
    else:
        for name, msg in flags:
            short = name[:55]
            print(f"  ⚠  [{short}]")
            print(f"     {msg}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Rmax safety sweep — find the ceiling that kills the extreme-mint runaway
# ─────────────────────────────────────────────────────────────────────────────

def rmax_safety_sweep() -> List[dict]:
    """
    Scenario 13: near-zero utilization (U=0.01) + massive QCB burn (Q=5000/tick).
    At U=0.01, U_bar→0.01, Rt → R0*(0.70/0.01)^gamma → clamped at Rmax.
    Sweep Rmax to find where supply growth becomes acceptable.
    """
    rmax_values = [1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 8.0, 10.0]
    results = []
    for rmax in rmax_values:
        p = Params(Rmax=rmax)
        u_fn = lambda r, t: 0.01
        q_fn = lambda t: 5000.0
        r = run_scenario(p, u_fn, q_fn, scenario_name=f"Rmax={rmax}")
        r["Rmax"] = rmax
        results.append(r)
    return results


def print_rmax_sweep(results: List[dict]):
    print(f"\n{'═'*70}")
    print("  Rmax Safety Sweep (Scenario 13: U=0.01, Q=5000/tick)")
    print(f"  Goal: find Rmax where supply growth stays < 2x (200%) at T=200")
    print(f"{'═'*70}")
    print(f"  {'Rmax':>6}  {'S_final':>14}  {'Δ%':>9}  {'Eq?':>4}  Note")
    print(f"  {'─'*58}")
    for r in results:
        dp = pct_change(r["S_init"], r["S_final"])
        eq = "✓" if r["equilibrium"] else "✗"
        change = (r["S_final"] - r["S_init"]) / r["S_init"]
        note = ""
        if change > 2.0:
            note = "⚠ RUNAWAY"
        elif change > 0.5:
            note = "⚠ HIGH"
        elif change < 0.05:
            note = "⚠ DEFLATIONARY"
        else:
            note = "✓ ACCEPTABLE"
        print(f"  {r['Rmax']:>6.1f}  {r['S_final']:>14,.0f}  {dp:>9}  {eq:>4}  {note}")


def main():
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    print("CIRFI Economic Model v0.1 — Stress-Test Simulation")
    print("=" * 60)

    print_parameter_table()

    # Base parameter set
    base = Params()

    print(f"\nRunning {200}-tick simulation across 15 scenarios...")
    results = run_all(base, verbose=verbose)

    print_summary_table(results, "15-Scenario Stress Test (T=200 ticks, S0=1,000,000)")
    print_risk_flags(results)

    # Gamma sweep
    print("\nRunning γ sweep...")
    gsweep = gamma_sweep(verbose=False)
    print_gamma_sweep(gsweep)

    # Rmax safety sweep
    print("\nRunning Rmax safety sweep...")
    rmax_results = rmax_safety_sweep()
    print_rmax_sweep(rmax_results)

    # Alpha sweep summary
    print(f"\n{'═'*70}")
    print("  Alpha (EMA) Sensitivity — Spike Recovery (scenarios 7, 14, 15)")
    print(f"{'═'*70}")
    spike_results = [r for r in results if "spike" in r["scenario"].lower() or
                     "EMA" in r["scenario"]]
    for r in spike_results:
        dp = pct_change(r["S_init"], r["S_final"])
        eq = "✓" if r["equilibrium"] else "✗"
        print(f"  {r['scenario'][:65]}")
        print(f"    S_final={r['S_final']:,.0f}  ({dp})  Eq={eq}  "
              f"tail_dS={r['tail_mean_dS']/r['S_init']*100:+.3f}%/tick")

    print(f"\n{'═'*70}")
    print("  Simulation complete.")
    print(f"{'═'*70}")
    print()
    print("Open parameters requiring calibration:")
    open_params = [
        ("gamma",    "1.5 (default)",  "Controls how aggressively Rt adjusts to congestion"),
        ("alpha",    "0.10 (default)", "EMA smoothing — higher = more reactive to spikes"),
        ("Rmin",     "0.5",            "Floor on CIRFI/QCB rate — prevents free minting"),
        ("Rmax",     "5.0",            "Ceiling on CIRFI/QCB rate — prevents hyperinflation"),
        ("p_burn",   "0.25",           "Fraction of consumption that permanently burns CIRFI"),
        ("p_res",    "0.15",           "Fraction going to protocol reserve"),
        ("beta",     "1.0",            "Congestion multiplier slope for provider earning"),
        ("R0",       "per-resource",   "Base conversion rate at U=U_star"),
        ("BaseRate", "per-resource",   "Provider earning rate per unit consumed"),
        ("w(r)",     "see above",      "Resource weight in provider earning formula"),
    ]
    print(f"  {'Parameter':<12}  {'Default':<18}  {'Note'}")
    print(f"  {'─'*65}")
    for name, default, note in open_params:
        print(f"  {name:<12}  {default:<18}  {note}")
    print()


if __name__ == "__main__":
    main()
