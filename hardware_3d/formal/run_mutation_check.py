#!/usr/bin/env python3
"""Mutation adequacy check for the Vertical Trust Guard formal harness (roadmap 1.2).

Each mutant injects one realistic security bug into a copy of
rtl/vertical_trust_guard.sv. The unmodified RTL must PASS the unbounded proof
(task 'prove', abc pdr). Every mutant must FAIL the bounded check (task 'bmc',
smtbmc), which also writes a counterexample trace; a surviving mutant means a
property gap. (bmc is used for mutants because it yields portable VCD traces.)

Usage (sby/yosys with the slang plugin on PATH):
    python run_mutation_check.py [--keep]
"""
import argparse
import json
import pathlib
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
RTL = HERE.parent / "rtl"

MUTANTS = [
    ("auth_check_removed", "end else if (!auth_ok_i) begin", "end else if (1'b0) begin"),
    ("epoch_check_removed", "end else if (epoch_i != active_epoch_i) begin", "end else if (1'b0) begin"),
    ("replay_window_accepts_any_newer",
     "end else if (sequence_i != (last_sequence[requester_i] + 32'd1)) begin",
     "end else if (sequence_i <= last_sequence[requester_i]) begin"),
    ("lockdown_not_sticky", "lockdown_q <= 1'b1;", "lockdown_q <= 1'b0;"),
    ("zeroize_disconnected", "key_zeroize_o  = severe_event_o;", "key_zeroize_o  = 1'b0;"),
    ("dma_reaches_key_tier",
     "REQ_DMA:       policy_ok = (layer_role_i[layer_i] == C3D_LAYER_ROLE_DATA);",
     "REQ_DMA:       policy_ok = 1'b1;"),
    ("dma_reaches_exec_tier",
     "REQ_DMA:       policy_ok = (layer_role_i[layer_i] == C3D_LAYER_ROLE_DATA);",
     "REQ_DMA:       policy_ok = (layer_role_i[layer_i] != C3D_LAYER_ROLE_KEY_HIDE);"),
    ("debug_unlock_ignored", "REQ_DEBUG:     policy_ok = debug_unlocked_i &&", "REQ_DEBUG:     policy_ok = 1'b1 &&"),
    ("fetch_may_write", "REQ_CPU_FETCH: policy_ok = !op_write_i &&", "REQ_CPU_FETCH: policy_ok = 1'b1 &&"),
    ("sentinel_fault_ignored", "end else if (sentinel_fault_i) begin", "end else if (1'b0) begin"),
    ("thermal_alarm_inverted", "if (temperature_mc_i[l] > MAX_TEMP_SIGNED)", "if (temperature_mc_i[l] < MAX_TEMP_SIGNED)"),
    ("policy_deny_desyncs_sequence", "consume_sequence = 1'b1;", "consume_sequence = policy_ok;"),
    ("auth_fail_not_severe",
     "deny_reason_o = DENY_AUTH;\n        request_severe = 1'b1;",
     "deny_reason_o = DENY_AUTH;\n        request_severe = 1'b0;"),
]


def run_sby(workdir: pathlib.Path, task: str) -> str:
    proc = subprocess.run(["sby", "-f", "vertical_trust_guard.sby", task], cwd=workdir,
                          capture_output=True, text=True, timeout=1800)
    out = proc.stdout + proc.stderr
    if "DONE (PASS" in out:
        return "PASS"
    if "DONE (FAIL" in out:
        return "FAIL"
    return "ERROR"


def stage(dst: pathlib.Path, guard_src: str) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    (dst / "formal").mkdir(parents=True)
    (dst / "rtl").mkdir()
    for f in ("vertical_trust_guard.sby", "vertical_trust_guard_props.sv"):
        shutil.copy(HERE / f, dst / "formal" / f)
    shutil.copy(RTL / "crypto3d_stack_pkg.sv", dst / "rtl")
    (dst / "rtl" / "vertical_trust_guard.sv").write_text(guard_src, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="keep mutant work directories")
    a = ap.parse_args()
    original = (RTL / "vertical_trust_guard.sv").read_text(encoding="utf-8").replace("\r\n", "\n")
    work = HERE / "mutation_work"
    results = []

    stage(work / "baseline", original)
    base = run_sby(work / "baseline" / "formal", "prove")
    print(f"baseline (unmodified RTL): {base}")
    ok = base == "PASS"

    for name, old, new in MUTANTS:
        if old not in original:
            print(f"{name}: SKIP (pattern not found)")
            results.append({"mutant": name, "result": "PATTERN_NOT_FOUND"})
            ok = False
            continue
        stage(work / name, original.replace(old, new, 1))
        res = run_sby(work / name / "formal", "bmc")
        killed = res == "FAIL"
        ok &= killed
        print(f"{name}: proof {res} -> {'KILLED' if killed else 'SURVIVED'}")
        results.append({"mutant": name, "proof": res, "killed": killed})

    killed = sum(1 for r in results if r.get("killed"))
    summary = {"baseline": base, "mutants": len(MUTANTS), "killed": killed, "results": results}
    (HERE / "mutation_results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"mutation score: {killed}/{len(MUTANTS)}")
    if not a.keep:
        shutil.rmtree(work, ignore_errors=True)
    print("[FORMAL MUTATION CHECK PASS]" if ok else "[FORMAL MUTATION CHECK FAIL]")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
