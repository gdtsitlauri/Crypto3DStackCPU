#!/usr/bin/env python3
"""Independent Python reference for VTF memory encryption + integrity tree (roadmap 2.1).

Construction (Bonsai-style Merkle tree over per-block counters):
  K_enc  = AES_{K_root}("VTFMEMENCKEY" || 00000001)
  K_mac  = AES_{K_root}("VTFMEMMACKEY" || 00000001)
  K_tree = AES_{K_root}("VTFMEMTREEKY" || 00000001)

  block i (128 bit), write counter c_i (32 bit, 0 = never written)
  keystream  = AES_{K_enc}(i || c_i || "CTRK" || "VTF3")
  ct_i       = pt_i XOR keystream                       (AES-CTR, fresh counter per write)
  mac_i      = CMAC_{K_mac}(ct_i || i || c_i || "DMAC" || "VTF3")
  leaf_i     = c_i || i || "CTR0" || "LEAF"
  node       = CMAC_{K_tree}(left || right)             (binary tree, BLOCKS leaves)
  root       = top node, kept ON-CHIP (key tier); everything else is untrusted storage

A read verifies the counter path up to the on-chip root, then the data MAC, then
decrypts. A write verifies the old path, encrypts with c_i+1, recomputes the
path and commits the new root. Splicing breaks mac_i (binds i). Replay or
rollback of (ct, mac, c, nodes) breaks the root.

  python hardware_3d/scripts/mem_integrity_reference.py --self-test
  python hardware_3d/scripts/mem_integrity_reference.py --emit-sv hardware_3d/tb/mit_vectors.svh
  python hardware_3d/scripts/mem_integrity_reference.py --emit-cpp src/mit_vectors.h
"""
from __future__ import annotations

import argparse
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

TEST_ROOT = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")
BLOCKS = 16


def aes(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def cmac(key: bytes, msg: bytes) -> bytes:
    c = CMAC(algorithms.AES(key))
    c.update(msg)
    return c.finalize()


def mem_keys(root: bytes) -> tuple[bytes, bytes, bytes]:
    one = struct.pack(">I", 1)
    return (aes(root, b"VTFMEMENCKEY" + one), aes(root, b"VTFMEMMACKEY" + one),
            aes(root, b"VTFMEMTREEKY" + one))


class IntegrityTamper(Exception):
    pass


class MemIntegrity:
    """Trusted engine; `self.ext_*` is the untrusted off-chip storage an attacker may edit."""

    def __init__(self, root_key: bytes = TEST_ROOT, blocks: int = BLOCKS):
        assert blocks >= 2 and blocks & (blocks - 1) == 0
        self.B = blocks
        self.D = blocks.bit_length() - 1
        self.k_enc, self.k_mac, self.k_tree = mem_keys(root_key)
        self.ext_ct = [bytes(16)] * blocks
        self.ext_mac = [bytes(16)] * blocks
        self.ext_ctr = [0] * blocks
        self.ext_node = [bytes(16)] * (blocks - 2)   # all tree nodes except the root
        self.root = self._build()

    # level l >= 1 holds B >> l nodes at offset B - (B >> (l - 1))
    def _off(self, level: int) -> int:
        return self.B - (self.B >> (level - 1))

    @staticmethod
    def leaf(i: int, ctr: int) -> bytes:
        return struct.pack(">II", ctr, i) + b"CTR0" + b"LEAF"

    def _build(self) -> bytes:
        prev = [self.leaf(i, self.ext_ctr[i]) for i in range(self.B)]
        for level in range(1, self.D + 1):
            cur = [cmac(self.k_tree, prev[2 * j] + prev[2 * j + 1]) for j in range(len(prev) // 2)]
            if level < self.D:
                for j, n in enumerate(cur):
                    self.ext_node[self._off(level) + j] = n
            prev = cur
        return prev[0]

    def _path(self, blk: int, ctr: int, sibs: list[bytes] | None = None):
        """Return (computed_root, siblings, nodes_on_path)."""
        h = self.leaf(blk, ctr)
        idx = blk
        got_sibs, nodes = [], []
        for level in range(self.D):
            if sibs is not None:
                sib = sibs[level]
            elif level == 0:
                sib = self.leaf(idx ^ 1, self.ext_ctr[idx ^ 1])
            else:
                sib = self.ext_node[self._off(level) + (idx ^ 1)]
            got_sibs.append(sib)
            h = cmac(self.k_tree, sib + h if idx & 1 else h + sib)
            idx >>= 1
            nodes.append(h)
        return h, got_sibs, nodes

    def keystream(self, blk: int, ctr: int) -> bytes:
        return aes(self.k_enc, struct.pack(">II", blk, ctr) + b"CTRK" + b"VTF3")

    def data_mac(self, blk: int, ctr: int, ct: bytes) -> bytes:
        return cmac(self.k_mac, ct + struct.pack(">II", blk, ctr) + b"DMAC" + b"VTF3")

    def read(self, blk: int) -> bytes:
        ct, mac, ctr = self.ext_ct[blk], self.ext_mac[blk], self.ext_ctr[blk]
        r, _, _ = self._path(blk, ctr)
        if r != self.root:
            raise IntegrityTamper("counter path does not match on-chip root")
        if ctr == 0:
            return bytes(16)
        if self.data_mac(blk, ctr, ct) != mac:
            raise IntegrityTamper("data MAC mismatch")
        return bytes(a ^ b for a, b in zip(ct, self.keystream(blk, ctr)))

    def write(self, blk: int, pt: bytes) -> None:
        old = self.ext_ctr[blk]
        r, sibs, _ = self._path(blk, old)
        if r != self.root:
            raise IntegrityTamper("counter path does not match on-chip root")
        if old == 0xFFFFFFFF:
            raise IntegrityTamper("counter exhausted; re-key required")
        ctr = old + 1
        ct = bytes(a ^ b for a, b in zip(pt, self.keystream(blk, ctr)))
        mac = self.data_mac(blk, ctr, ct)
        new_root, _, nodes = self._path(blk, ctr, sibs)
        idx = blk
        for level in range(1, self.D):
            idx >>= 1
            self.ext_node[self._off(level) + idx] = nodes[level - 1]
        self.ext_ct[blk], self.ext_mac[blk], self.ext_ctr[blk] = ct, mac, ctr
        self.root = new_root


SCRIPT = [
    (2, bytes.fromhex("00112233445566778899aabbccddeeff")),
    (5, bytes.fromhex("deadbeefcafebabe0123456789abcdef")),
    (2, bytes.fromhex("a5a5a5a55a5a5a5a0f0f0f0ff0f0f0f0")),
    (15, bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")),
]


def run_script() -> tuple[MemIntegrity, list[bytes], bytes]:
    m = MemIntegrity()
    init_root = m.root
    roots = []
    for blk, pt in SCRIPT:
        m.write(blk, pt)
        roots.append(m.root)
    return m, roots, init_root


def self_test() -> bool:
    ok = True
    m, roots, _ = run_script()
    ok &= m.read(2) == SCRIPT[2][1] and m.read(5) == SCRIPT[1][1] and m.read(0) == bytes(16)
    ok &= m.ext_ct[2] != SCRIPT[2][1]

    def detects(attack) -> bool:
        mm, _, _ = run_script()
        target = attack(mm)
        try:
            mm.read(target)
            return False
        except IntegrityTamper:
            return True

    def flip_ct(mm):
        mm.ext_ct[5] = bytes([mm.ext_ct[5][0] ^ 1]) + mm.ext_ct[5][1:]
        return 5

    def splice(mm):
        mm.ext_ct[15], mm.ext_mac[15] = mm.ext_ct[5], mm.ext_mac[5]
        return 15

    def rollback(mm):
        mm.ext_ctr[2] = 1
        return 2

    def replay(mm):
        snap = (mm.ext_ct[2], mm.ext_mac[2], mm.ext_ctr[2], list(mm.ext_node))
        mm.write(2, bytes(16))
        mm.ext_ct[2], mm.ext_mac[2], mm.ext_ctr[2], mm.ext_node = snap[0], snap[1], snap[2], snap[3]
        return 2

    for name, atk in [("bitflip", flip_ct), ("splice", splice), ("rollback", rollback), ("replay", replay)]:
        d = detects(atk)
        print(f"  attack {name}: {'detected' if d else 'MISSED'}")
        ok &= d
    print("[MIT REFERENCE SELF-TEST PASS]" if ok else "[MIT REFERENCE SELF-TEST FAIL]")
    return ok


def h(b: bytes) -> str:
    return b.hex()


def emit_sv(path: str) -> None:
    m, roots, init_root = run_script()
    ke, km, kt = mem_keys(TEST_ROOT)
    L = ["// Generated by hardware_3d/scripts/mem_integrity_reference.py --emit-sv (do not edit).",
         f"localparam logic [127:0] MIT_K_ENC = 128'h{h(ke)};",
         f"localparam logic [127:0] MIT_K_MAC = 128'h{h(km)};",
         f"localparam logic [127:0] MIT_K_TREE = 128'h{h(kt)};",
         f"localparam logic [127:0] MIT_ROOT_INIT = 128'h{h(init_root)};",
         f"localparam int MIT_NSCRIPT = {len(SCRIPT)};"]
    L.append("localparam logic [3:0] MIT_SCRIPT_BLK [4] = '{" + ", ".join(f"4'd{b}" for b, _ in SCRIPT) + "};")
    L.append("localparam logic [127:0] MIT_SCRIPT_PT [4] = '{" + ", ".join(f"128'h{h(p)}" for _, p in SCRIPT) + "};")
    L.append("localparam logic [127:0] MIT_SCRIPT_ROOT [4] = '{" + ", ".join(f"128'h{h(r)}" for r in roots) + "};")
    L.append(f"localparam logic [127:0] MIT_CT2 = 128'h{h(m.ext_ct[2])};")
    L.append(f"localparam logic [127:0] MIT_MAC2 = 128'h{h(m.ext_mac[2])};")
    with open(path, "w", newline="\n") as f:
        f.write("\n".join(L) + "\n")
    print(f"wrote {path}")


def emit_cpp(path: str) -> None:
    m, roots, init_root = run_script()

    def w4(b: bytes) -> str:
        return "{" + ",".join(f"0x{x:08x}u" for x in struct.unpack(">4I", b)) + "}"
    L = ["// Generated by hardware_3d/scripts/mem_integrity_reference.py --emit-cpp (do not edit).",
         "#pragma once", "#include <cstdint>", "namespace mit_vectors {",
         f"static const uint32_t ROOT_INIT[4] = {w4(init_root)};",
         f"static const unsigned SCRIPT_BLK[4] = {{{', '.join(str(b) for b, _ in SCRIPT)}}};",
         "static const uint32_t SCRIPT_PT[4][4] = {" + ", ".join(w4(p) for _, p in SCRIPT) + "};",
         "static const uint32_t SCRIPT_ROOT[4][4] = {" + ", ".join(w4(r) for r in roots) + "};",
         f"static const uint32_t CT2[4] = {w4(m.ext_ct[2])};",
         f"static const uint32_t MAC2[4] = {w4(m.ext_mac[2])};",
         "}  // namespace mit_vectors"]
    with open(path, "w", newline="\n") as f:
        f.write("\n".join(L) + "\n")
    print(f"wrote {path}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--emit-sv")
    ap.add_argument("--emit-cpp")
    a = ap.parse_args()
    ok = True
    if a.self_test or not (a.emit_sv or a.emit_cpp):
        ok = self_test()
    if a.emit_sv:
        emit_sv(a.emit_sv)
    if a.emit_cpp:
        emit_cpp(a.emit_cpp)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
