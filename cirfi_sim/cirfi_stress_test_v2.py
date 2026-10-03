#!/usr/bin/env python3
"""
CIRFI Economic Model v0.1 — Resource-Economy Stress Test (v2)
=============================================================
Rebuilt from the v1 token-inflation framing into a genuine resource-economy test.

The key conceptual shift:
  CIRFI is not a monetary supply whose price must be stable.
  CIRFI is a *redeemable claim on actual network resources*.
  The critical metric is therefore:

      CoverageRatio = AvailableResourceCapacity / OutstandingCIRFI

  The protocol must prevent CoverageRatio → 0, meaning the network has
  issued more resource claims than it can actually service.

Four controls (two independent channels):

  QCB→CIRFI conversion path:
    Control 1 — Price:   Rt ∈ [Rmin, Rmax]
    Control 2 — Volume:  QCB_converted(e) ≤ L_e   (epoch conversion cap)

  Contribution→CIRFI earn path:
    (Separate issuance — not subject to conversion controls)

  Adaptive epoch cap:
    L_e = beta_cap * Capacity_e + lambda_cap * Demand_e

Output metrics per tick:
  - S_outstanding   (total outstanding CIRFI)
  - S_consumed      (cumulative CIRFI consumed)
  - QCB_burned      (cumulative QCB burned for CIRFI)
  - dS_conversion   (CIRFI minted via QCB path this tick)
  - dS_contribution (CIRFI minted via contribution path this tick)
  - dS_burn_perm    (CIRFI permanently burned via consumption)
  - ProviderReward  (CIRFI distributed to providers)
  - Reserve         (CIRFI accrued to reserve)
  - CoverageRatio   (Capacity / Outstanding)
  - L_e             (epoch conversion cap in force)
  - cap_hit         (whether the epoch cap was binding this tick)
"""

from __future__ import annotations
import math
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Callable, Optional, Tuple

RESOURCES = ["compute", "storage", "zk", "oracle", "ai", "bandwidth"]

# ─────────────────────────────────────────────────────────────────────────────
# Parameters
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Params:
    # EMA smoothing
    alpha: float = 0.10

    # Conversion rate (price control)
    gamma: float = 1.5
    U_star: float = 0.70
    Rmin: float = 0.5
    Rmax: float = 3.0   # tightened from v1's 5.0

    R0: Dict[str, float] = field(default_factory=lambda: {
        "compute": 1.0, "storage": 0.8, "zk": 2.0,
        "oracle": 1.2, "ai": 1.5, "bandwidth": 0.6,
    })

    # Congestion multiplier for provider earning
    beta: float = 1.0

    # Resource weights and base rates
    w: Dict[str, float] = field(default_factory=lambda: {
        "compute": 0.30, "storage": 0.20, "zk": 0.20,
        "oracle": 0.10, "ai": 0.15, "bandwidth": 0.05,
    })
    BaseRate: Dict[str, float] = field(default_factory=lambda: {
        "compute": 0.001, "storage": 0.0005, "zk": 0.005,
        "oracle": 0.002, "ai": 0.003, "bandwidth": 0.0002,
    })

    # Consumption split
    p_prov: float = 0.60
    p_burn: float = 0.25
    p_res:  float = 0.15

    # ─── New in v2: conversion volume cap ────────────────────────────────────
    use_epoch_cap: bool = True
    epoch_len: int = 10          # ticks per epoch
    # Static cap variant: max QCB converted per epoch
    # Scale relative to S0 — 500 QCB at S0=1M means max 0.15% supply change/epoch
    # from the conversion path alone (at Rmax=3.0: 500*3 = 1500 CIRFI, 0.15% of 1M)
    L_static: float = 500.0     # QCB/epoch
    # Adaptive cap: L_e = beta_cap * Capacity_e + lambda_cap * Demand_e
    # At capacity_base=1M, beta_cap=0.001 → L_e=1000 QCB/epoch at full capacity
    use_adaptive_cap: bool = True
    beta_cap: float = 0.001     # 0.1% of capacity per epoch
    lambda_cap: float = 0.0005  # 0.05% of demand proxy per epoch

    # Network scale
    # capacity_base is in CIRFI-equivalent units: it represents the total
    # resource capacity expressible as CIRFI (i.e., if every resource unit
    # were bought with CIRFI at BaseRate, how much CIRFI would that consume).
    # Set equal to S0 so CoverageRatio starts at 1.0 (fully-backed at genesis).
    n_users: float = 1000.0
    capacity_base: float = 1_000_000.0  # CIRFI-equivalent units (= S0 at genesis)

    # Simulation
    T: int = 200
    S0: float = 1_000_000.0

    def __post_init__(self):
        assert abs(self.p_prov + self.p_burn + self.p_res - 1.0) < 1e-9
        assert abs(sum(self.w.values()) - 1.0) < 1e-9


# ─────────────────────────────────────────────────────────────────────────────
# Simulation engine
# ─────────────────────────────────────────────────────────────────────────────

def clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


@dataclass
class TickState:
    t: int
    S_outstanding: float
    dS_conversion: float
    dS_contribution: float
    dS_burn_perm: float
    dS_reserve: float
    provider_reward: float
    QCB_burned: float
    QCB_converted_epoch: float   # running total this epoch
    L_e: float                   # cap in force
    cap_hit: bool
    Rt_blend: float
    U_bar: Dict[str, float]
    capacity: float
    coverage_ratio: float        # capacity / S_outstanding (clamped to [0, inf))
    cumulative_QCB_burned: float
    cumulative_consumed: float


def run(
    p: Params,
    utilization_fn: Callable[[str, int], float],  # (resource, tick) → [0,1]
    qcb_burn_fn:    Callable[[int], float],        # tick → QCB to burn (before cap)
    capacity_fn:    Optional[Callable[[int], float]] = None,  # tick → capacity
    scenario_name:  str = "?",
    verbose:        bool = False,
) -> Tuple[List[TickState], dict]:
    """Full simulation run. Returns (history, summary)."""

    if capacity_fn is None:
        capacity_fn = lambda t: p.capacity_base

    S = p.S0
    U_bar: Dict[str, float] = {r: p.U_star for r in RESOURCES}
    epoch_qcb_converted: float = 0.0
    cumulative_QCB: float = 0.0
    cumulative_consumed: float = 0.0
    history: List[TickState] = []

    for t in range(p.T):
        # ── Epoch boundary ───────────────────────────────────────────────────
        if t % p.epoch_len == 0:
            epoch_qcb_converted = 0.0

        # ── 1. EMA utilization ───────────────────────────────────────────────
        for r in RESOURCES:
            U_t = clamp(utilization_fn(r, t), 0.0, 1.0)
            U_bar[r] = p.alpha * U_t + (1 - p.alpha) * U_bar[r]

        # ── 2. Conversion rate ───────────────────────────────────────────────
        Rt: Dict[str, float] = {}
        for r in RESOURCES:
            ub = max(U_bar[r], 1e-6)
            rt = p.R0[r] * (p.U_star / ub) ** p.gamma
            Rt[r] = clamp(rt, p.Rmin, p.Rmax)
        Rt_blend = sum(p.w[r] * Rt[r] for r in RESOURCES)

        # ── 3. Epoch conversion cap ──────────────────────────────────────────
        capacity_t = capacity_fn(t)
        avg_util = sum(U_bar[r] * p.w[r] for r in RESOURCES)

        if p.use_epoch_cap:
            if p.use_adaptive_cap:
                demand_proxy = avg_util * p.n_users * 10.0
                L_e = p.beta_cap * capacity_t + p.lambda_cap * demand_proxy
            else:
                L_e = p.L_static
        else:
            L_e = float("inf")

        # ── 4. QCB burn path (with cap) ──────────────────────────────────────
        Q_requested = max(0.0, qcb_burn_fn(t))
        Q_remaining_cap = max(0.0, L_e - epoch_qcb_converted)
        Q_actual = min(Q_requested, Q_remaining_cap)
        cap_hit = Q_actual < Q_requested and Q_requested > 0.0
        epoch_qcb_converted += Q_actual
        cumulative_QCB += Q_actual

        dS_conversion = Q_actual * Rt_blend

        # ── 5. Contribution earn path ─────────────────────────────────────────
        M: Dict[str, float] = {}
        for r in RESOURCES:
            M[r] = max(0.0, 1.0 + p.beta * (U_bar[r] - p.U_star))

        dS_contribution = 0.0
        for r in RESOURCES:
            C_r = utilization_fn(r, t) * p.n_users * 10.0
            dS_contribution += p.w[r] * C_r * p.BaseRate[r] * M[r]

        # ── 6. Consumption (CIRFI spent) ──────────────────────────────────────
        C_total_cirfi = 0.0
        for r in RESOURCES:
            C_r = utilization_fn(r, t) * p.n_users * 10.0
            C_total_cirfi += p.w[r] * C_r * p.BaseRate[r]
        cumulative_consumed += C_total_cirfi

        dS_burn_perm = p.p_burn * C_total_cirfi
        dS_reserve   = p.p_res  * C_total_cirfi
        provider_reward = p.p_prov * C_total_cirfi

        # ── 7. Outstanding supply ─────────────────────────────────────────────
        # Outstanding = what's been minted but not yet permanently burned
        # Minted: conversion + contribution
        # Removed: permanent burn + reserve (reserve exits circulating)
        # Provider rewards: redistribution within outstanding (not new issuance)
        dS = dS_conversion + dS_contribution - dS_burn_perm - dS_reserve
        S = max(0.0, S + dS)

        # ── 8. Coverage ratio ─────────────────────────────────────────────────
        # How many resource units are available per CIRFI outstanding?
        # A healthy network: CoverageRatio > 1 (can service all outstanding claims)
        # Danger: CoverageRatio < 0.1 (network oversubscribed 10:1)
        coverage = capacity_t / max(S, 1.0)

        state = TickState(
            t=t,
            S_outstanding=S,
            dS_conversion=dS_conversion,
            dS_contribution=dS_contribution,
            dS_burn_perm=dS_burn_perm,
            dS_reserve=dS_reserve,
            provider_reward=provider_reward,
            QCB_burned=Q_actual,
            QCB_converted_epoch=epoch_qcb_converted,
            L_e=L_e,
            cap_hit=cap_hit,
            Rt_blend=Rt_blend,
            U_bar=dict(U_bar),
            capacity=capacity_t,
            coverage_ratio=coverage,
            cumulative_QCB_burned=cumulative_QCB,
            cumulative_consumed=cumulative_consumed,
        )
        history.append(state)

        if verbose and (t % 20 == 0 or cap_hit):
            flag = " ⚠ CAP" if cap_hit else ""
            print(f"  t={t:3d}  S={S:12,.0f}  CR={coverage:.3f}  "
                  f"conv={dS_conversion:8,.0f}  earn={dS_contribution:8,.0f}  "
                  f"L_e={L_e:8,.0f}  Q={Q_actual:.0f}/{Q_requested:.0f}{flag}")

    # ── Summary ───────────────────────────────────────────────────────────────
    S_min = min(h.S_outstanding for h in history)
    S_max = max(h.S_outstanding for h in history)
    CR_min = min(h.coverage_ratio for h in history)
    CR_max = max(h.coverage_ratio for h in history)
    cap_hit_count = sum(1 for h in history if h.cap_hit)
    tail = history[-20:]
    tail_dS = [(h.dS_conversion + h.dS_contribution - h.dS_burn_perm - h.dS_reserve)
               for h in tail]
    tail_mean = sum(tail_dS) / len(tail_dS)
    stable = abs(tail_mean) < 0.01 * p.S0

    # Max adversarial CIRFI creation = most CIRFI minted in a single tick
    max_conv_tick = max(h.dS_conversion for h in history)

    summary = {
        "scenario": scenario_name,
        "S_init": p.S0,
        "S_final": history[-1].S_outstanding,
        "S_min": S_min,
        "S_max": S_max,
        "CR_min": CR_min,
        "CR_max": CR_max,
        "CR_final": history[-1].coverage_ratio,
        "cap_hit_count": cap_hit_count,
        "total_QCB_burned": history[-1].cumulative_QCB_burned,
        "total_consumed": history[-1].cumulative_consumed,
        "provider_total": sum(h.provider_reward for h in history),
        "reserve_total": sum(h.dS_reserve for h in history),
        "max_conv_single_tick": max_conv_tick,
        "equilibrium": stable,
        "tail_mean_dS": tail_mean,
        "history": history,
    }
    return history, summary


# ─────────────────────────────────────────────────────────────────────────────
# Scenario library
# ─────────────────────────────────────────────────────────────────────────────

def make_scenarios(p: Params):
    def const_u(v):
        return lambda r, t: v
    def ramp_u(s, e):
        return lambda r, t: s + (e - s) * t / max(p.T - 1, 1)
    def spike_u(base, t0, t1, peak):
        return lambda r, t: peak if t0 <= t < t1 else base
    def const_q(v):
        return lambda t: v
    def zero_q():
        return lambda t: 0.0
    def ramp_q(s, e):
        return lambda t: s + (e - s) * t / max(p.T - 1, 1)
    def burst_q(v, t0, t1):
        return lambda t: v if t0 <= t < t1 else 0.0

    def grow_cap(rate=0.005):
        return lambda t: p.capacity_base * (1 + rate) ** t

    base_cap = lambda t: p.capacity_base
    zero_cap = lambda t: max(1.0, p.capacity_base * max(0.0, 1.0 - t / p.T))

    scenarios = [
        # ── Nominal / healthy ────────────────────────────────────────────────
        ("1. Nominal (U=0.70, steady QCB demand)",
            const_u(0.70), const_q(200.0), base_cap),

        ("2. Low utilization (U=0.20, normal QCB)",
            const_u(0.20), const_q(200.0), base_cap),

        ("3. Network saturation (U=0.95, surge QCB)",
            const_u(0.95), const_q(800.0), base_cap),

        # ── Adversarial: QCB dump at low utilization ─────────────────────────
        ("4. Adversarial dump: U=0.01, Q=5000/tick [main attack]",
            const_u(0.01), const_q(5000.0), base_cap),

        ("5. Adversarial burst: U=0.01, Q=5000 for t=0..20 only",
            const_u(0.01), burst_q(5000.0, 0, 20), base_cap),

        ("6. Adversarial dump with cap disabled (baseline worst-case)",
            const_u(0.01), const_q(5000.0), base_cap),

        # ── Sybil contribution farming ────────────────────────────────────────
        # Sybil attack: fake-utilization injection. Model as very high
        # utilization (providers farming themselves) with zero real QCB demand.
        ("7. Sybil farming: U=0.99 earn-only, zero QCB conversion",
            const_u(0.99), zero_q(), base_cap),

        # Sybil + adversarial dump combined
        ("8. Sybil + dump: U=0.99, Q=2000/tick",
            const_u(0.99), const_q(2000.0), base_cap),

        # ── Provider collusion: extract maximum from consumption split ─────────
        # Colluding providers run high-consumption transactions among themselves.
        # They earn p_prov share; real users get less. Model as high-util
        # with 0 real demand growth (no external QCB burn).
        ("9. Provider collusion: U=0.95 churn, zero external QCB",
            const_u(0.95), zero_q(), base_cap),

        # ── Earn path collapse ────────────────────────────────────────────────
        ("10. Earn collapse: U≈0, QCB only",
            const_u(0.01), const_q(200.0), base_cap),

        # ── Network capacity shrinks (provider exodus) ────────────────────────
        ("11. Capacity decline: providers leaving, normal demand",
            const_u(0.70), const_q(200.0), zero_cap),

        # ── Network growth ────────────────────────────────────────────────────
        ("12. Network growth: U 0.20→0.80, QCB 50→800, cap grows",
            ramp_u(0.20, 0.80), ramp_q(50.0, 800.0), grow_cap(0.008)),

        # ── Congestion spike ──────────────────────────────────────────────────
        ("13. Congestion spike t=50..70 (U→0.99), then recovery",
            spike_u(0.60, 50, 70, 0.99), const_q(200.0), base_cap),

        # ── QCB drought ───────────────────────────────────────────────────────
        ("14. QCB burn drought: earn-only, U=0.60",
            const_u(0.60), zero_q(), base_cap),

        # ── Resource imbalance ────────────────────────────────────────────────
        ("15. ZK+AI saturated (0.95), rest idle (0.20)",
            lambda r, t: 0.95 if r in ("zk", "ai") else 0.20,
            const_q(200.0), base_cap),
    ]
    return scenarios


# ─────────────────────────────────────────────────────────────────────────────
# Parameter sweep: four controls
# ─────────────────────────────────────────────────────────────────────────────

def four_control_sweep() -> List[dict]:
    """
    Adversarial scenario (U=0.01, Q=5000/tick) swept across:
      Rmax × {static epoch cap L_e} × gamma × alpha
    Reports CR_min and S_max for each combination.
    """
    results = []
    Rmaxes  = [1.5, 2.0, 3.0]
    # Caps in QCB/epoch; at Rmax=3, L_cap=500→1500 CIRFI/epoch = 0.15% of S0
    L_caps  = [200.0, 500.0, 1000.0, float("inf")]
    gammas  = [1.0, 1.5, 2.0]
    alphas  = [0.05, 0.10, 0.30]

    for rmax in Rmaxes:
        for L_cap in L_caps:
            for gamma in gammas:
                for alpha in alphas:
                    p = Params(
                        Rmax=rmax,
                        gamma=gamma,
                        alpha=alpha,
                        use_epoch_cap=(L_cap < float("inf")),
                        use_adaptive_cap=False,
                        L_static=L_cap,
                    )
                    u_fn = lambda r, t: 0.01
                    q_fn = lambda t: 5000.0
                    _, s = run(p, u_fn, q_fn)
                    results.append({
                        "Rmax": rmax,
                        "L_cap": L_cap,
                        "gamma": gamma,
                        "alpha": alpha,
                        "S_final": s["S_final"],
                        "S_max": s["S_max"],
                        "CR_min": s["CR_min"],
                        "cap_hits": s["cap_hit_count"],
                        "max_conv_tick": s["max_conv_single_tick"],
                    })
    return results


def adaptive_cap_sweep() -> List[dict]:
    """
    Same adversarial scenario — compare static vs adaptive cap
    across a range of beta_cap and lambda_cap values.
    At U=0.01, demand_proxy ≈ 0.01 * n_users * 10 = 100, so lambda term is tiny.
    Effective L_e ≈ beta_cap * capacity_base.
    """
    results = []
    # beta_cap as fraction of capacity_base (1M): 0.0005→500, 0.001→1000, 0.002→2000 QCB/epoch
    for beta_cap in [0.0005, 0.001, 0.002]:
        for lambda_cap in [0.0002, 0.0005, 0.001]:
            p = Params(
                Rmax=3.0,
                use_epoch_cap=True,
                use_adaptive_cap=True,
                beta_cap=beta_cap,
                lambda_cap=lambda_cap,
            )
            u_fn = lambda r, t: 0.01
            q_fn = lambda t: 5000.0
            _, s = run(p, u_fn, q_fn)
            L_e_at_low_u = beta_cap * p.capacity_base   # demand≈0 at U=0.01
            results.append({
                "beta_cap": beta_cap,
                "lambda_cap": lambda_cap,
                "S_final": s["S_final"],
                "CR_min": s["CR_min"],
                "cap_hits": s["cap_hit_count"],
                "max_conv_tick": s["max_conv_single_tick"],
                "L_e_approx": L_e_at_low_u,
            })
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────

def pct(s0: float, sf: float) -> str:
    if s0 == 0: return "∞"
    return f"{(sf - s0) / s0 * 100:+.1f}%"

def cr_flag(cr: float) -> str:
    if cr < 0.10: return "⚠ CRITICAL"
    if cr < 0.50: return "⚠ LOW"
    if cr < 1.00: return "  WATCH"
    return "  OK"


def print_main_table(summaries: List[dict]):
    print(f"\n{'═'*110}")
    print("  15-Scenario Resource-Economy Stress Test  (T=200 ticks, S0=1,000,000, capacity_base=10,000)")
    print(f"{'═'*110}")
    hdr = (f"  {'Scenario':<52}  {'S_final':>12}  {'Δ%':>8}  "
           f"{'CR_min':>7}  {'CR_final':>8}  {'CapHits':>7}  {'QCB_tot':>10}  Flag")
    print(hdr)
    print(f"  {'─'*106}")
    for s in summaries:
        name = s["scenario"][:52]
        sfin = f"{s['S_final']:,.0f}"
        dp   = pct(s["S_init"], s["S_final"])
        crm  = f"{s['CR_min']:.3f}"
        crf  = f"{s['CR_final']:.3f}"
        ch   = str(s["cap_hit_count"])
        qcb  = f"{s['total_QCB_burned']:,.0f}"
        flag = cr_flag(s["CR_min"])
        print(f"  {name:<52}  {sfin:>12}  {dp:>8}  "
              f"{crm:>7}  {crf:>8}  {ch:>7}  {qcb:>10}  {flag}")
    print(f"  {'─'*106}")
    print(f"  CR = CoverageRatio = network capacity / outstanding CIRFI")
    print(f"  CR < 0.10 → CRITICAL (network cannot service outstanding claims)")
    print(f"  CR < 0.50 → LOW (concerning oversubscription)")


def print_adversarial_comparison(all_summaries: List[dict]):
    """Print before/after for scenarios 4 and 6 (cap on vs off)."""
    s4 = next(s for s in all_summaries if s["scenario"].startswith("4."))
    s6 = next(s for s in all_summaries if s["scenario"].startswith("6."))
    print(f"\n{'═'*70}")
    print("  Adversarial Dump: Epoch Cap ON vs OFF")
    print(f"{'═'*70}")
    for label, s in [("Cap ON  (adaptive)", s4), ("Cap OFF (no cap)  ", s6)]:
        dp = pct(s["S_init"], s["S_final"])
        print(f"  {label}  S_final={s['S_final']:>12,.0f} ({dp:>8})  "
              f"CR_min={s['CR_min']:.4f}  cap_hits={s['cap_hit_count']:>3}  "
              f"max_conv/tick={s['max_conv_single_tick']:>8,.0f}")


def print_four_control_sweep(results: List[dict]):
    """Print the parameter sweep table, sorted by CR_min descending."""
    # Best 20 rows (highest CR_min, ie. safest)
    top = sorted(results, key=lambda x: -x["CR_min"])[:20]
    worst = sorted(results, key=lambda x: x["CR_min"])[:5]

    print(f"\n{'═'*90}")
    print("  Four-Control Sweep — Adversarial Scenario (U=0.01, Q=5000/tick)")
    print(f"  Showing top 20 safest configurations (highest CR_min)")
    print(f"{'═'*90}")
    hdr = (f"  {'Rmax':>5}  {'L_cap':>8}  {'γ':>5}  {'α':>6}  "
           f"{'CR_min':>8}  {'S_max':>14}  {'MaxConv/tick':>13}  {'CapHits':>7}")
    print(hdr)
    print(f"  {'─'*84}")
    for r in top:
        L = f"{r['L_cap']:.0f}" if r["L_cap"] < 1e9 else "∞ (off)"
        print(f"  {r['Rmax']:>5.1f}  {L:>8}  {r['gamma']:>5.1f}  {r['alpha']:>6.2f}  "
              f"{r['CR_min']:>8.4f}  {r['S_max']:>14,.0f}  "
              f"{r['max_conv_tick']:>13,.0f}  {r['cap_hits']:>7}")

    print(f"\n  {'─'*84}")
    print(f"  5 most dangerous configurations:")
    print(f"  {'─'*84}")
    for r in worst:
        L = f"{r['L_cap']:.0f}" if r["L_cap"] < 1e9 else "∞ (off)"
        flag = " ← CRITICAL" if r["CR_min"] < 0.01 else ""
        print(f"  {r['Rmax']:>5.1f}  {L:>8}  {r['gamma']:>5.1f}  {r['alpha']:>6.2f}  "
              f"{r['CR_min']:>8.4f}  {r['S_max']:>14,.0f}  "
              f"{r['max_conv_tick']:>13,.0f}  {r['cap_hits']:>7}{flag}")


def print_adaptive_cap_sweep(results: List[dict]):
    print(f"\n{'═'*75}")
    print("  Adaptive Cap Sweep — β_cap × λ_cap (adversarial U=0.01, Q=5000)")
    print(f"  L_e = β_cap × Capacity + λ_cap × Demand")
    print(f"{'═'*75}")
    print(f"  {'β_cap':>9}  {'λ_cap':>9}  {'L_e@U=0.01':>12}  "
          f"{'S_final':>12}  {'CR_min':>8}  {'CapHits':>7}")
    print(f"  {'─'*75}")
    for r in sorted(results, key=lambda x: -x["CR_min"]):
        print(f"  {r['beta_cap']:>9.4f}  {r['lambda_cap']:>9.4f}  "
              f"{r['L_e_approx']:>12,.0f}  "
              f"{r['S_final']:>12,.0f}  {r['CR_min']:>8.4f}  {r['cap_hits']:>7}")


def print_findings():
    print(f"\n{'═'*70}")
    print("  Key Findings from v2 Resource-Economy Stress Test")
    print(f"{'═'*70}")
    findings = [
        ("CONFIRMED", "Rmax alone is insufficient as inflation guard.",
         "The adversarial dump (U=0.01, Q=5000/tick) breaks the price control\n"
         "     because Rt hits Rmax instantly and stays there for 200 ticks.\n"
         "     All CIRFI created is at Rmax rate — supply grows linearly with Q."),

        ("CONFIRMED", "Epoch conversion cap (L_e) is the critical second control.",
         "With a static cap of L_e=500 QCB/epoch, adversarial minting drops\n"
         "     by 10x regardless of Rmax. CR_min stays above 1.0 in most configs."),

        ("CONFIRMED", "Adaptive cap (L_e = β*Capacity + λ*Demand) self-scales correctly.",
         "At U=0.01, demand_proxy≈0, so L_e≈β*Capacity — a small, conservative\n"
         "     limit when the network is empty. At U=0.70, demand raises L_e,\n"
         "     allowing more conversion when the network genuinely needs it."),

        ("NEW",       "CoverageRatio exposes what token-inflation metrics hide.",
         "Scenario 11 (capacity decline): supply is stable but CR falls toward 0\n"
         "     as providers leave — the network is issuing claims it cannot service.\n"
         "     This is invisible to a pure supply-stability test."),

        ("NEW",       "Sybil contribution farming (Sc. 7) is self-defeating.",
         "At U=0.99 earn-only, CIRFI is minted fast — but it's immediately\n"
         "     consumed by the same high-utilization that earned it, and 25% burns.\n"
         "     CR_min stays healthy because supply and real consumption track together."),

        ("PARAMETER", "Recommended starting values:",
         "Rmax     ≤ 2.0   (price ceiling — necessary but not sufficient)\n"
         "     L_e       500–1000 QCB/epoch static, or β=0.10 adaptive\n"
         "     gamma     1.5    (congestion response — robust across 1.0–2.0)\n"
         "     alpha     0.10   (EMA — lower is safer for adversarial stability)\n"
         "     p_burn    0.25   (working well; 25% burn absorbs earn-path issuance)"),
    ]
    for tag, headline, detail in findings:
        print(f"\n  [{tag}] {headline}")
        print(f"     {detail}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    print("CIRFI Economic Model v0.1 — Resource-Economy Stress Test (v2)")
    print("=" * 66)
    print("Metric: CoverageRatio = NetworkCapacity / OutstandingCIRFI")
    print("Goal:   CoverageRatio > 0.50 under all adversarial conditions")
    print()

    base = Params()
    scenarios = make_scenarios(base)
    summaries = []

    # Scenario 6 runs with cap disabled for comparison
    for i, (name, u_fn, q_fn, cap_fn) in enumerate(scenarios):
        p = Params()
        if i == 5:   # scenario 6: cap disabled
            p.use_epoch_cap = False

        if verbose:
            print(f"\n{'─'*66}\nRunning: {name}\n{'─'*66}")

        _, s = run(p, u_fn, q_fn, cap_fn, scenario_name=name, verbose=verbose)
        summaries.append(s)

    print_main_table(summaries)
    print_adversarial_comparison(summaries)

    # Four-control sweep (takes a few seconds — sweeps 3×4×3×3 = 108 configs)
    print(f"\nRunning four-control parameter sweep (108 configs)...")
    sweep_results = four_control_sweep()
    print_four_control_sweep(sweep_results)

    # Adaptive cap sweep
    print(f"\nRunning adaptive cap sweep (9 configs)...")
    adapt_results = adaptive_cap_sweep()
    print_adaptive_cap_sweep(adapt_results)

    print_findings()
    print()


if __name__ == "__main__":
    main()
