"""Parser checks for collect_hardware_results.py on representative report excerpts.

Run: python -m pytest hardware_3d/scripts/test_collect_hardware_results.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import collect_hardware_results as chr_  # noqa: E402

VIVADO_UTIL = """
1. Slice Logic
--------------

+-------------------------+------+-------+------------+-----------+-------+
|        Site Type        | Used | Fixed | Prohibited | Available | Util% |
+-------------------------+------+-------+------------+-----------+-------+
| Slice LUTs*             |  473 |     0 |          0 |    134600 |  0.35 |
|   LUT as Logic          |  473 |     0 |          0 |    134600 |  0.35 |
| Slice Registers         |  293 |     0 |          0 |    269200 |  0.11 |
+-------------------------+------+-------+------------+-----------+-------+

3. Memory
---------

+-------------------+------+-------+------------+-----------+-------+
|     Site Type     | Used | Fixed | Prohibited | Available | Util% |
+-------------------+------+-------+------------+-----------+-------+
| Block RAM Tile    |    4 |     0 |          0 |       365 |  1.10 |
|   RAMB36/FIFO*    |    4 |     0 |          0 |       365 |  1.10 |
+-------------------+------+-------+------------+-----------+-------+

4. DSP
------
| DSPs      |    0 |     0 |          0 |       740 |  0.00 |
"""

VIVADO_TIMING = """
------------------------------------------------------------------------------------------------
| Design Timing Summary
| ---------------------
------------------------------------------------------------------------------------------------

    WNS(ns)      TNS(ns)  TNS Failing Endpoints  TNS Total Endpoints      WHS(ns)
    -------      -------  ---------------------  -------------------      -------
      6.214        0.000                      0                  512        0.112
"""

HLS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<profile>
  <UserAssignments>
    <unit>ns</unit><Part>xc7a200t-fbg676-2</Part><TopModelName>crypto3d_vtf_cmac_verify</TopModelName>
    <TargetClockPeriod>10.00</TargetClockPeriod>
  </UserAssignments>
  <PerformanceEstimates>
    <SummaryOfTimingAnalysis><unit>ns</unit><EstimatedClockPeriod>7.300</EstimatedClockPeriod></SummaryOfTimingAnalysis>
    <SummaryOfOverallLatency>
      <Best-caseLatency>420</Best-caseLatency><Worst-caseLatency>431</Worst-caseLatency>
      <Interval-min>421</Interval-min><Interval-max>432</Interval-max>
    </SummaryOfOverallLatency>
  </PerformanceEstimates>
  <AreaEstimates><Resources><BRAM_18K>2</BRAM_18K><DSP>0</DSP><FF>1500</FF><LUT>3200</LUT><URAM>0</URAM></Resources></AreaEstimates>
</profile>
"""


def test_vivado_parsers():
    assert chr_.parse_vivado_utilization(VIVADO_UTIL) == {"lut": 473, "ff": 293, "bram_tile": 4, "dsp": 0}
    assert chr_.parse_vivado_timing(VIVADO_TIMING) == {"wns_ns": 6.214, "tns_ns": 0.0}


def test_hls_and_yosys_parsers():
    hls = chr_.parse_hls_csynth(HLS_XML)
    assert hls["top"] == "crypto3d_vtf_cmac_verify"
    assert hls["lut"] == 3200 and hls["ff"] == 1500 and hls["latency_worst_cycles"] == 431
    block = "\n   477 cells\n   473   $lut\n     4   RAMB36E1\n    12   CARRY4\n   293   FDRE\n"
    assert chr_.parse_yosys_stat(block) == {"lut": 473, "ramb36e1": 4, "carry4": 12, "ff": 293}
    # Real `stat` output repeats the totals in a design-hierarchy block.
    stat = "=== crypto3d_secure_stack_top ===\n" + block + "\n=== design hierarchy ===\n" + block
    assert chr_.parse_yosys_stat(stat)["lut"] == 473


def test_collect_overhead(tmp_path):
    viv = tmp_path / "vivado"
    for top, lut, ff in (("crypto3d_secure_stack_top", 473, 293), ("crypto3d_unprotected_stack_top", 106, 36)):
        d = viv / top
        d.mkdir(parents=True)
        (d / "utilization_synth.rpt").write_text(VIVADO_UTIL.replace("473", str(lut)).replace("293", str(ff)))
        (d / "timing_synth.rpt").write_text(VIVADO_TIMING)
    (viv / "run_manifest.txt").write_text("part=xc7a200tfbg676-2\nperiod_ns=10.0\n")
    rtl = tmp_path / "rtl"
    rtl.mkdir()
    (rtl / "attack_campaign.csv").write_text(
        "scenario,variant,detected,deny_reason,lockdown,zeroize,integrity_preserved\n"
        "valid_write,protected,0,0,0,0,1\nvalid_write,unprotected,0,0,0,0,1\n"
        "replay,protected,1,4,1,1,1\nreplay,unprotected,0,0,0,0,0\n")
    s = chr_.collect(tmp_path)
    chr_.write_reports(s, tmp_path)
    assert s["vtf_overhead"]["synth"]["lut"] == 473 - 106
    assert s["vtf_overhead"]["synth"]["ff"] == 293 - 36
    assert s["attack_campaign"]["protected_detected"] == 1
    assert s["attack_campaign"]["unprotected_integrity_preserved"] == 0
    assert (tmp_path / "table_vtf_overhead.tex").exists()
