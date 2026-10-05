#!/usr/bin/env python3
"""RO-PUF model + code-offset fuzzy extractor for the device root key (roadmap 2.4).

Simulation only. Real reliability/uniqueness needs many boards and temperatures (phase 3).

PUF model (ring-oscillator pairs, disjoint pairs so bits are independent):
  f_i = f0 * (1 + sigma_p * N(0,1))                      per-device process variation
  f_i(T) = f_i * (1 + tc_i * (T - 25))                   per-oscillator temperature coefficient
  read: f_i(T) + f0 * sigma_n * N(0,1)                   measurement noise
  bit_j = [f_{2j} > f_{2j+1}]

Fuzzy extractor (code-offset, Dodis et al.):
  enrolment : w = PUF response (128*REP bits), s = 128 random bits,
              helper h = w XOR Rep_REP(s)                (public, stored in NVM)
  reconstruct: s' = MajorityDecode(w' XOR h)             corrects floor(REP/2) errors per block
  K_root = CMAC_{0^128}(s' || "VTFPUFKEYDERIVE1")        (privacy amplification/decorrelation)
With iid unbiased PUF bits each REP-bit block keeps 1 bit of entropy after the
helper is published, so 128 blocks give a 128-bit secret.

  python hardware_3d/scripts/puf_fuzzy_extractor.py --study
  python hardware_3d/scripts/puf_fuzzy_extractor.py --emit-sv hardware_3d/tb/puf_vectors.svh
"""
from __future__ import annotations

import argparse
import json
import math
import random
import sys

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC

KEY_BITS = 128
LABEL = b"VTFPUFKEYDERIVE1"


class ROPUF:
    def __init__(self, device_seed: int, bits: int, sigma_p=0.01, sigma_n=0.0012, tc_sigma=2e-5):
        rng = random.Random(device_seed)
        self.n = bits
        self.f = [1.0 + sigma_p * rng.gauss(0, 1) for _ in range(2 * bits)]
        self.tc = [tc_sigma * rng.gauss(0, 1) for _ in range(2 * bits)]
        self.sigma_n = sigma_n
        self.noise = random.Random(device_seed ^ 0x5EED)

    def read(self, temp_c: float = 25.0) -> list[int]:
        out = []
        for j in range(self.n):
            a = self.f[2 * j] * (1 + self.tc[2 * j] * (temp_c - 25)) + self.sigma_n * self.noise.gauss(0, 1)
            b = self.f[2 * j + 1] * (1 + self.tc[2 * j + 1] * (temp_c - 25)) + self.sigma_n * self.noise.gauss(0, 1)
            out.append(1 if a > b else 0)
        return out


def bits_to_int(bits: list[int]) -> int:
    v = 0
    for b in bits:
        v = (v << 1) | b
    return v


def kdf(secret_bits: list[int]) -> bytes:
    c = CMAC(algorithms.AES(bytes(16)))
    c.update(bits_to_int(secret_bits).to_bytes(16, "big") + LABEL)
    return c.finalize()


def enroll(w: list[int], rep: int, rng: random.Random) -> tuple[list[int], list[int]]:
    s = [rng.getrandbits(1) for _ in range(KEY_BITS)]
    code = [b for b in s for _ in range(rep)]
    return s, [x ^ y for x, y in zip(w, code)]


def reconstruct(w2: list[int], helper: list[int], rep: int) -> list[int]:
    c = [x ^ y for x, y in zip(w2, helper)]
    return [1 if sum(c[i * rep:(i + 1) * rep]) * 2 > rep else 0 for i in range(KEY_BITS)]


def hd(a: list[int], b: list[int]) -> int:
    return sum(x != y for x, y in zip(a, b))


def study(rep_list=(1, 3, 5, 7, 9, 11), devices=40, reads=50) -> dict:
    res = {"model": "RO-PUF, disjoint pairs, sigma_p=1%, sigma_n=0.12%, tc_sigma=2e-5/C",
           "devices": devices, "reads_per_condition": reads, "per_rep": {}}
    nbits = KEY_BITS * max(rep_list)
    puf = [ROPUF(1000 + d, nbits) for d in range(devices)]
    ref = [p.read(25.0) for p in puf]
    # uniqueness: mean pairwise inter-device HD (fraction)
    inter = [hd(ref[i], ref[j]) / nbits for i in range(devices) for j in range(i + 1, devices)]
    res["uniqueness_inter_hd"] = sum(inter) / len(inter)
    res["bias_ones_fraction"] = sum(sum(r) for r in ref) / (devices * nbits)
    temps = [-20.0, 25.0, 85.0]
    intra = {t: [] for t in temps}
    noisy = {t: [[p.read(t) for _ in range(reads)] for p in puf] for t in temps}
    for t in temps:
        for d in range(devices):
            intra[t] += [hd(ref[d], x) / nbits for x in noisy[t][d]]
    res["reliability_intra_hd"] = {str(t): sum(v) / len(v) for t, v in intra.items()}
    rng = random.Random(7)
    for rep in rep_list:
        fails = {str(t): 0 for t in temps}
        total = 0
        for d in range(devices):
            w = ref[d][:KEY_BITS * rep]
            s, h = enroll(w, rep, rng)
            for t in temps:
                for x in noisy[t][d]:
                    if reconstruct(x[:KEY_BITS * rep], h, rep) != s:
                        fails[str(t)] += 1
            total += reads
        res["per_rep"][str(rep)] = {"puf_bits": KEY_BITS * rep,
                                    "key_failure_rate": {t: f / total for t, f in fails.items()},
                                    "residual_entropy_bits_iid_model": KEY_BITS}
    return res


def emit_sv(path: str, rep: int = 11) -> None:
    rng = random.Random(2026)
    puf = ROPUF(4242, KEY_BITS * rep)
    w = puf.read(25.0)
    s, h = enroll(w, rep, rng)
    noisy = puf.read(85.0)          # hot re-read with errors
    errs = hd(w, noisy)
    s2 = reconstruct(noisy, h, rep)
    assert s2 == s, "chosen vector must reconstruct"
    key = kdf(s)
    # a response from another device must not give the key
    other = ROPUF(9999, KEY_BITS * rep).read(25.0)
    key_other = kdf(reconstruct(other, h, rep))
    nb = KEY_BITS * rep
    L = ["// Generated by hardware_3d/scripts/puf_fuzzy_extractor.py --emit-sv (do not edit).",
         f"localparam int PUF_REP = {rep};",
         f"localparam logic [{nb - 1}:0] PUF_HELPER = {nb}'h{bits_to_int(h):0{nb // 4}x};",
         f"localparam logic [{nb - 1}:0] PUF_NOISY = {nb}'h{bits_to_int(noisy):0{nb // 4}x};  // {errs} bit errors vs enrolment",
         f"localparam logic [{nb - 1}:0] PUF_OTHER = {nb}'h{bits_to_int(other):0{nb // 4}x};",
         f"localparam logic [127:0] PUF_SECRET = 128'h{bits_to_int(s):032x};",
         f"localparam logic [127:0] PUF_KEY = 128'h{key.hex()};",
         f"localparam logic [127:0] PUF_KEY_OTHER = 128'h{key_other.hex()};"]
    with open(path, "w", newline="\n") as f:
        f.write("\n".join(L) + "\n")
    print(f"wrote {path} ({errs} injected bit errors in {nb} PUF bits)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--study", action="store_true")
    ap.add_argument("--out")
    ap.add_argument("--emit-sv")
    a = ap.parse_args()
    if a.emit_sv:
        emit_sv(a.emit_sv)
    if a.study:
        r = study()
        print(f"uniqueness (inter-HD) = {r['uniqueness_inter_hd']:.3f}, bias = {r['bias_ones_fraction']:.3f}")
        print("reliability (intra-HD):", {k: round(v, 4) for k, v in r["reliability_intra_hd"].items()})
        for rep, v in r["per_rep"].items():
            print(f"  REP={rep:>2} ({v['puf_bits']} bits): key failure rate", v["key_failure_rate"])
        if a.out:
            with open(a.out, "w", encoding="utf-8") as f:
                json.dump(r, f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
