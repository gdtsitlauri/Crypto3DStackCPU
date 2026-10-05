#!/usr/bin/env python3
"""Collect hardware-gate evidence into one summary (standard library only).

Reads whatever exists under <results>/ (default results/hardware_eval):
  rtl/attack_campaign.csv, rtl/*.log, rtl/yosys_<top>.stat   (run_rtl_validation.*)
  vivado/<top>/utilization_{synth,impl}.rpt, timing_*.rpt, power_impl.rpt
  hls/vtf_cmac/sol1/syn/report/*csynth.xml (+ impl/report export reports)
and writes summary.json, summary.md and table_vtf_overhead.tex next to them.
Missing stages are reported as "not_run"; nothing is estimated or filled in.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

TOPS = ["crypto3d_unprotected_stack_top", "crypto3d_secure_stack_top", "vertical_trust_guard"]

_UTIL_ROWS = {
    "lut": r"(?:Slice LUTs|CLB LUTs)\*?",
    "ff": r"(?:Slice Registers|CLB Registers|Register as Flip Flop)",
    "bram_tile": r"Block RAM Tile",
    "dsp": r"DSPs",
}


def parse_vivado_utilization(text: str) -> Dict[str, float]:
    out: Dict[str, float] = {}
    for key, label in _UTIL_ROWS.items():
        m = re.search(rf"^\|\s*{label}\s*\|\s*([\d.]+)\s*\|", text, re.MULTILINE)
        if m:
            out[key] = float(m.group(1)) if "." in m.group(1) else int(m.group(1))
    return out


def parse_vivado_timing(text: str) -> Dict[str, Optional[float]]:
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if "WNS(ns)" in line and "TNS(ns)" in line:
            for nxt in lines[i + 1:i + 4]:
                vals = nxt.split()
                if vals and not set(vals[0]) <= {"-"}:
                    try:
                        return {"wns_ns": float(vals[0]), "tns_ns": float(vals[1])}
                    except ValueError:
                        return {"wns_ns": None, "tns_ns": None}
    return {}


def parse_vivado_power(text: str) -> Dict[str, float]:
    out = {}
    for key, label in {"total_power_w": "Total On-Chip Power (W)", "dynamic_power_w": "Dynamic (W)"}.items():
        m = re.search(rf"\|\s*{re.escape(label)}\s*\|\s*([\d.]+)", text)
        if m:
            out[key] = float(m.group(1))
    return out


def parse_yosys_stat(text: str) -> Dict[str, int]:
    # `stat` prints one "=== module ===" block per module and then a
    # "design hierarchy" block repeating the totals; count only the last block.
    blocks = [b for b in re.split(r"^===.*===\s*$", text, flags=re.MULTILINE)
              if re.search(r"^\s+\d+\s+\S+\s*$", b, re.MULTILINE)]
    text = blocks[-1] if blocks else ""
    out: Dict[str, int] = {}
    luts = 0
    for m in re.finditer(r"^\s+(\d+)\s+(\S+)\s*$", text, re.MULTILINE):
        n, cell = int(m.group(1)), m.group(2)
        if cell == "$lut" or re.fullmatch(r"LUT[1-6]", cell):
            luts += n
        elif cell in {"FDRE", "FDSE", "FDCE", "FDPE"}:
            out["ff"] = out.get("ff", 0) + n
        elif cell in {"RAMB36E1", "RAMB18E1", "CARRY4"}:
            out[cell.lower()] = out.get(cell.lower(), 0) + n
    if luts:
        out["lut"] = luts
    return out


def parse_hls_csynth(xml_text: str) -> Dict[str, Any]:
    root = ET.fromstring(xml_text)

    def find(path: str) -> Optional[str]:
        el = root.find(path)
        return el.text.strip() if el is not None and el.text else None

    def num(v: Optional[str]):
        if v is None:
            return None
        try:
            return int(v)
        except ValueError:
            try:
                return float(v)
            except ValueError:
                return v

    res = {
        "top": find("./UserAssignments/TopModelName"),
        "part": find("./UserAssignments/Part"),
        "target_clock_ns": num(find("./UserAssignments/TargetClockPeriod")),
        "estimated_clock_ns": num(find("./PerformanceEstimates/SummaryOfTimingAnalysis/EstimatedClockPeriod")),
        "latency_best_cycles": num(find("./PerformanceEstimates/SummaryOfOverallLatency/Best-caseLatency")),
        "latency_worst_cycles": num(find("./PerformanceEstimates/SummaryOfOverallLatency/Worst-caseLatency")),
        "interval_min_cycles": num(find("./PerformanceEstimates/SummaryOfOverallLatency/Interval-min")),
        "interval_max_cycles": num(find("./PerformanceEstimates/SummaryOfOverallLatency/Interval-max")),
    }
    for r in ("LUT", "FF", "BRAM_18K", "DSP", "URAM"):
        res[r.lower()] = num(find(f"./AreaEstimates/Resources/{r}"))
    return res


def parse_hls_export(text: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key in ("LUT", "FF", "DSP", "BRAM", "SRL", "URAM", "CLB", "SLICE"):
        m = re.search(rf"^\s*{key}\s*:\s*(\d+)", text, re.MULTILINE)
        if m:
            out[key.lower()] = int(m.group(1))
    m = re.search(r"CP achieved post-(?:synthesis|implementation)\s*:\s*([\d.]+)", text)
    if m:
        out["achieved_clock_ns"] = float(m.group(1))
    return out


def read(path: Path) -> Optional[str]:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else None


def collect(results: Path) -> Dict[str, Any]:
    summary: Dict[str, Any] = {"results_dir": str(results)}

    # --- RTL validation / attack campaign ---------------------------------
    rtl = results / "rtl"
    campaign_csv = rtl / "attack_campaign.csv"
    if campaign_csv.exists():
        rows = list(csv.DictReader(campaign_csv.open(encoding="utf-8")))
        attacks = [r for r in rows if r["scenario"] != "valid_write"]
        prot = [r for r in attacks if r["variant"] == "protected"]
        unprot = [r for r in attacks if r["variant"] == "unprotected"]
        summary["attack_campaign"] = {
            "scenarios": len(prot),
            "protected_detected": sum(int(r["detected"]) for r in prot),
            "protected_integrity_preserved": sum(int(r["integrity_preserved"]) for r in prot),
            "unprotected_detected": sum(int(r["detected"]) for r in unprot),
            "unprotected_integrity_preserved": sum(int(r["integrity_preserved"]) for r in unprot),
            "false_positive_on_valid_write": any(
                r["scenario"] == "valid_write" and int(r["detected"]) for r in rows),
            "rows": rows,
        }
        logs = {tb: read(rtl / f"{tb}.log") or "" for tb in
                ("tb_vertical_trust_guard", "tb_stacked_memory_3d_model", "tb_vtf_attack_campaign")}
        summary["rtl_simulation"] = {tb: ("[SV TEST PASS]" in t) for tb, t in logs.items()}
    else:
        summary["attack_campaign"] = "not_run"

    yosys = {top: parse_yosys_stat(read(rtl / f"yosys_{top}.stat") or "") for top in TOPS}
    summary["yosys_estimate"] = {k: v for k, v in yosys.items() if v} or "not_run"

    # --- Vivado -----------------------------------------------------------
    viv = results / "vivado"
    vivado: Dict[str, Any] = {}
    for top in TOPS:
        d = viv / top
        entry: Dict[str, Any] = {}
        for stage in ("synth", "impl"):
            util = read(d / f"utilization_{stage}.rpt")
            timing = read(d / f"timing_{stage}.rpt")
            if util:
                entry[stage] = {**parse_vivado_utilization(util), **parse_vivado_timing(timing or "")}
        power = read(d / "power_impl.rpt")
        if power:
            entry.setdefault("impl", {}).update(parse_vivado_power(power))
        if entry:
            vivado[top] = entry
    manifest = read(viv / "run_manifest.txt")
    if manifest:
        vivado["manifest"] = dict(l.split("=", 1) for l in manifest.splitlines() if "=" in l and not l.startswith("completed"))
    summary["vivado"] = vivado or "not_run"

    # Overhead of the guard = secure - unprotected, per available stage.
    if isinstance(summary["vivado"], dict):
        period = float(vivado.get("manifest", {}).get("period_ns", 10.0))
        overhead = {}
        for stage in ("impl", "synth"):
            a = vivado.get("crypto3d_secure_stack_top", {}).get(stage)
            b = vivado.get("crypto3d_unprotected_stack_top", {}).get(stage)
            if a and b:
                overhead[stage] = {k: a[k] - b[k] for k in ("lut", "ff", "bram_tile", "dsp") if k in a and k in b}
                for name, rep in (("secure", a), ("unprotected", b)):
                    if rep.get("wns_ns") is not None:
                        overhead[stage][f"fmax_mhz_{name}"] = round(1000.0 / (period - rep["wns_ns"]), 1)
        summary["vtf_overhead"] = overhead or "not_run"

    # --- Vitis HLS (CMAC authenticator) -----------------------------------
    hls_root = results / "hls" / "vtf_cmac" / "sol1"
    xmls = sorted((hls_root / "syn" / "report").glob("*csynth.xml")) if hls_root.exists() else []
    top_xml = [p for p in xmls if p.name.startswith("crypto3d_vtf_cmac_verify")] or [p for p in xmls if p.name == "csynth.xml"]
    hls: Dict[str, Any] = {}
    if top_xml:
        hls["csynth"] = parse_hls_csynth(top_xml[0].read_text(encoding="utf-8"))
        clk = hls["csynth"].get("estimated_clock_ns")
        lat = hls["csynth"].get("latency_worst_cycles")
        if isinstance(clk, (int, float)) and isinstance(lat, (int, float)):
            hls["csynth"]["latency_worst_ns"] = round(clk * lat, 1)
    exports = sorted((hls_root / "impl" / "report").rglob("*export*.rpt")) if hls_root.exists() else []
    if exports:
        hls["post_synthesis"] = parse_hls_export(exports[0].read_text(encoding="utf-8", errors="replace"))
    for name in ("csim", "cosim"):
        logs = sorted(hls_root.rglob(f"{name}*.log")) if hls_root.exists() else []
        if logs:
            hls[f"{name}_pass"] = any("HLS CSIM PASS" in p.read_text(errors="replace") or
                                     "*** C/RTL co-simulation finished: PASS ***" in p.read_text(errors="replace")
                                     for p in logs)
    summary["hls_cmac"] = hls or "not_run"
    return summary


def write_reports(summary: Dict[str, Any], results: Path) -> None:
    (results / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    md: List[str] = ["# Crypto3DStackCPU hardware-gate summary", ""]
    ac = summary.get("attack_campaign")
    if isinstance(ac, dict):
        md += [f"Attack campaign: protected detected {ac['protected_detected']}/{ac['scenarios']}, "
               f"integrity preserved {ac['protected_integrity_preserved']}/{ac['scenarios']}; "
               f"unprotected detected {ac['unprotected_detected']}/{ac['scenarios']}, "
               f"integrity preserved {ac['unprotected_integrity_preserved']}/{ac['scenarios']}; "
               f"false positive on valid write: {ac['false_positive_on_valid_write']}.", ""]
    md += ["| Source | Top | Stage | LUT | FF | BRAM tiles / RAMB36 | WNS (ns) |", "|---|---|---|---|---|---|---|"]
    if isinstance(summary.get("vivado"), dict):
        for top in TOPS:
            for stage, rep in summary["vivado"].get(top, {}).items():
                md.append(f"| Vivado | {top} | {stage} | {rep.get('lut', '')} | {rep.get('ff', '')} | "
                          f"{rep.get('bram_tile', '')} | {rep.get('wns_ns', '')} |")
    if isinstance(summary.get("yosys_estimate"), dict):
        for top, rep in summary["yosys_estimate"].items():
            md.append(f"| Yosys estimate | {top} | synth | {rep.get('lut', '')} | {rep.get('ff', '')} | "
                      f"{rep.get('ramb36e1', '')} | |")
    hls = summary.get("hls_cmac")
    if isinstance(hls, dict) and "csynth" in hls:
        c = hls["csynth"]
        md += ["", f"HLS AES-CMAC verify: LUT {c.get('lut')}, FF {c.get('ff')}, BRAM18K {c.get('bram_18k')}, "
                   f"latency {c.get('latency_worst_cycles')} cycles at {c.get('estimated_clock_ns')} ns "
                   f"({c.get('latency_worst_ns')} ns)."]
    (results / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    ov = summary.get("vtf_overhead")
    if isinstance(ov, dict) and ov:
        stage = "impl" if "impl" in ov else "synth"
        v = summary["vivado"]
        a, b, d = v["crypto3d_secure_stack_top"][stage], v["crypto3d_unprotected_stack_top"][stage], ov[stage]
        tex = [
            "% Generated by hardware_3d/scripts/collect_hardware_results.py",
            "\\begin{tabular}{lrrrr}", "\\hline",
            "Design & LUT & FF & BRAM tiles & $F_{max}$ (MHz) \\\\", "\\hline",
            f"Unprotected stack & {b.get('lut', '--')} & {b.get('ff', '--')} & {b.get('bram_tile', '--')} & {d.get('fmax_mhz_unprotected', '--')} \\\\",
            f"VTF-protected stack & {a.get('lut', '--')} & {a.get('ff', '--')} & {a.get('bram_tile', '--')} & {d.get('fmax_mhz_secure', '--')} \\\\",
            f"Overhead & {d.get('lut', '--')} & {d.get('ff', '--')} & {d.get('bram_tile', '--')} & \\\\",
            "\\hline", "\\end{tabular}", f"% Vivado {stage}, part {v.get('manifest', {}).get('part', '?')}",
        ]
        (results / "table_vtf_overhead.tex").write_text("\n".join(tex) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results", default="results/hardware_eval")
    args = ap.parse_args()
    results = Path(args.results)
    summary = collect(results)
    write_reports(summary, results)
    print(json.dumps({k: v for k, v in summary.items() if k not in {"attack_campaign"}}, indent=2)[:4000])
    print(f"wrote {results / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
