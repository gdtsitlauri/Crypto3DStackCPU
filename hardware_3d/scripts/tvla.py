#!/usr/bin/env python3
"""Simulated TVLA (fixed-vs-random Welch t-test) for the masked AES S-box (roadmap 2.2).

Input: the log of tb/tb_tvla_sbox.sv, rows "T,class,m0..m9,u0..u9"
(class 0 = fixed input, 1 = random input; m = masked pipeline, u = unmasked
reference; each sample is the Hamming weight of all pipeline registers at one
cycle). Computes, per cycle sample:
  * first-order t   : Welch t on the raw samples
  * second-order t  : Welch t on the squared mean-free samples (univariate)
and reports max |t| against the usual 4.5 threshold.

Expected for a correct first-order masking: first-order |t| < 4.5 for the
masked design, |t| >> 4.5 for the unmasked one; second-order leakage of the
masked design is expected (first-order masking does not claim to resist it).

  python hardware_3d/scripts/tvla.py results/hardware_eval/tvla_sim/tvla_traces.log \
      --out results/hardware_eval/tvla_sim/tvla_summary.json
"""
from __future__ import annotations

import argparse
import json
import math
import sys

THRESHOLD = 4.5


def welch(a: list[float], b: list[float]) -> float:
    na, nb = len(a), len(b)
    ma, mb = sum(a) / na, sum(b) / nb
    va = sum((x - ma) ** 2 for x in a) / (na - 1)
    vb = sum((x - mb) ** 2 for x in b) / (nb - 1)
    den = math.sqrt(va / na + vb / nb)
    if den == 0.0:
        return 0.0 if ma == mb else math.inf
    return (ma - mb) / den


def analyse(rows: list[list[int]], offset: int, n: int) -> dict:
    fixed = [r for r in rows if r[0] == 0]
    rand = [r for r in rows if r[0] == 1]
    t1, t2 = [], []
    for k in range(n):
        a = [float(r[1 + offset + k]) for r in fixed]
        b = [float(r[1 + offset + k]) for r in rand]
        t1.append(welch(a, b))
        # centre on the pooled mean, as in standard higher-order TVLA preprocessing
        pooled = a + b
        mu = sum(pooled) / len(pooled)
        t2.append(welch([(x - mu) ** 2 for x in a], [(x - mu) ** 2 for x in b]))
    fin = lambda v: [x if math.isfinite(x) else 1e9 for x in v]
    return {"t_first_order": fin(t1), "t_second_order": fin(t2),
            "max_abs_t1": max(abs(x) for x in fin(t1)), "max_abs_t2": max(abs(x) for x in fin(t2))}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--out")
    a = ap.parse_args()
    rows = []
    with open(a.log, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("T,"):
                rows.append([int(x) for x in line.strip().split(",")[1:]])
    if len(rows) < 100:
        print(f"too few traces ({len(rows)})")
        return 1
    n = (len(rows[0]) - 1) // 2
    masked = analyse(rows, 0, n)
    unmasked = analyse(rows, n, n)
    nf = sum(1 for r in rows if r[0] == 0)
    res = {"traces": len(rows), "fixed": nf, "random": len(rows) - nf, "threshold": THRESHOLD,
           "masked": masked, "unmasked": unmasked,
           "masked_first_order_pass": masked["max_abs_t1"] < THRESHOLD,
           "unmasked_first_order_leaks": unmasked["max_abs_t1"] >= THRESHOLD,
           "model": "register Hamming-weight per cycle, simulation (no glitches/coupling/noise)"}
    print(f"traces={len(rows)} (fixed {nf}, random {len(rows) - nf})")
    print(f"unmasked: max|t1|={unmasked['max_abs_t1']:.1f}  max|t2|={unmasked['max_abs_t2']:.1f}")
    print(f"masked  : max|t1|={masked['max_abs_t1']:.2f}  max|t2|={masked['max_abs_t2']:.1f}")
    print("[TVLA FIRST-ORDER PASS]" if res["masked_first_order_pass"] and res["unmasked_first_order_leaks"]
          else "[TVLA FIRST-ORDER FAIL]")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2)
    return 0 if res["masked_first_order_pass"] and res["unmasked_first_order_leaks"] else 1


if __name__ == "__main__":
    sys.exit(main())
