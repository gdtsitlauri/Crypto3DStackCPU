#!/usr/bin/env python3
"""Program-level VTF overhead (roadmap 2.6): C++ CPU traces replayed on the RTL SoC.

For every programs/*.asm with a contract:
  1. assemble + seal + run the C++ CPU (src/3d.cpp) with C3D_VTF_TRACE set, which
     records every tier-crossing access (I-cache line fills, D-cache misses,
     write-through stores) and prints the architectural counters;
  2. replay the trace on the RTL CPU bridge + VTF system (tb/tb_vtf_soc.sv), which
     checks correctness and measures cycles per authenticated transaction;
  3. report the added cycles per retired instruction versus an unprotected
     memory port (BASE_LATENCY cycles per access, ready one cycle after request).

The CPU model counts a fixed cycle budget, so the meaningful normalisation is per
retired instruction (delta CPI), not a percentage of the reported cycles.

  python hardware_3d/scripts/vtf_trace_overhead.py --bin-dir <dir with asm_to_hex, encryptor, cpu>
         --vvp <compiled tb_vtf_soc.vvp> [--vvp-ft <FAULT_HARDEN=1 build>] --out results/hardware_eval/soc
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE_LATENCY = 2


ALIASES = {"asm_to_hex": ["asm_to_hex"], "encryptor": ["encryptor", "encryptor_single"],
           "cpu": ["cpu", "crypto3d_cpu_test", "3d_test_single"]}


def exe(bin_dir: pathlib.Path, name: str) -> str:
    for alias in ALIASES[name]:
        for cand in (alias + ".exe", alias):
            if (bin_dir / cand).exists():
                return str(bin_dir / cand)
    raise FileNotFoundError(f"{name} not found in {bin_dir}")


def run_program(bin_dir: pathlib.Path, asm: pathlib.Path, work: pathlib.Path) -> dict:
    stem = asm.stem
    text, data, image, trace = (work / f"{stem}.text.hex", work / f"{stem}.data.hex",
                                work / f"{stem}.hex", work / f"{stem}.trace")
    subprocess.run([exe(bin_dir, "asm_to_hex"), str(asm), str(text), str(data)], check=True,
                   capture_output=True, text=True)
    subprocess.run([exe(bin_dir, "encryptor"), str(text), str(data), str(image)], check=True,
                   capture_output=True, text=True)
    env = dict(os.environ, C3D_VTF_TRACE=str(trace))
    p = subprocess.run([exe(bin_dir, "cpu"), str(image), str(asm.with_suffix(".contract"))],
                       capture_output=True, text=True, env=env)
    out = p.stdout + p.stderr
    m = re.search(r"cycles=(\d+) retired=(\d+)", out)
    stats = {"program": stem, "cpu_pass": "[ALL TESTS PASSED]" in out,
             "cycles": int(m.group(1)) if m else None, "retired": int(m.group(2)) if m else None}
    for key in ("icache_misses", "dcache_misses", "dcache_hits", "icache_hits"):
        mm = re.search(key + r"=(\d+)", out)
        stats[key] = int(mm.group(1)) if mm else None
    kinds = {"F": 0, "R": 0, "W": 0}
    with open(trace) as f:
        for line in f:
            if line[:1] in kinds:
                kinds[line[0]] += 1
    stats.update({"trace_fetch": kinds["F"], "trace_load": kinds["R"], "trace_store": kinds["W"],
                  "trace_file": str(trace)})
    return stats


def replay(vvp: str, trace: str) -> dict:
    p = subprocess.run(["vvp", "-n", vvp, f"+TRACE={trace}"], capture_output=True, text=True)
    res = {"rtl_pass": "[SV TEST PASS]" in p.stdout}
    for line in p.stdout.splitlines():
        if line.startswith("METRIC,"):
            _, k, v = line.strip().split(",")
            res[k] = float(v)
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin-dir", required=True)
    ap.add_argument("--vvp", required=True)
    ap.add_argument("--vvp-ft")
    ap.add_argument("--out", default=str(ROOT / "results" / "hardware_eval" / "soc"))
    a = ap.parse_args()
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    work = out / "work"
    work.mkdir(exist_ok=True)
    rows, ok = [], True
    for asm in sorted((ROOT / "programs").glob("*.asm")):
        if not asm.with_suffix(".contract").exists():
            continue
        s = run_program(pathlib.Path(a.bin_dir), asm, work)
        for tag, v in (("", a.vvp), ("ft_", a.vvp_ft)):
            if not v:
                continue
            r = replay(v, s["trace_file"])
            lat = {k: r.get(f"{k}_cycles_avg", 0.0) for k in ("fetch", "load", "store")}
            added = (s["trace_fetch"] * (lat["fetch"] - BASE_LATENCY) + s["trace_load"] * (lat["load"] - BASE_LATENCY)
                     + s["trace_store"] * (lat["store"] - BASE_LATENCY))
            s[f"{tag}rtl_pass"] = r["rtl_pass"]
            s[f"{tag}fetch_cycles"] = lat["fetch"]
            s[f"{tag}load_cycles"] = lat["load"]
            s[f"{tag}store_cycles"] = lat["store"]
            s[f"{tag}added_cycles"] = added
            s[f"{tag}delta_cpi"] = added / s["retired"] if s["retired"] else None
            ok &= r["rtl_pass"]
        ok &= s["cpu_pass"]
        rows.append(s)
        print(f"{s['program']:>16}: retired={s['retired']} F/R/W={s['trace_fetch']}/{s['trace_load']}/"
              f"{s['trace_store']} rtl_pass={s.get('rtl_pass')} dCPI={s.get('delta_cpi', 0):.1f}"
              + (f" (FT dCPI={s['ft_delta_cpi']:.1f})" if 'ft_delta_cpi' in s else ""))
    keys = [k for k in rows[0].keys() if k != "trace_file"]
    with open(out / "vtf_program_overhead.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    with open(out / "vtf_program_overhead.json", "w") as f:
        json.dump({"base_latency_cycles": BASE_LATENCY, "programs": rows}, f, indent=2)
    print("[SOC TRACE OVERHEAD PASS]" if ok else "[SOC TRACE OVERHEAD FAIL]")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
