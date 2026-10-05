#pragma once
// Memory encryption + integrity tree (roadmap 2.1), C++ model.
//
// Same construction as hardware_3d/rtl/memory_integrity_tree.sv and the
// independent reference hardware_3d/scripts/mem_integrity_reference.py:
//   keystream = AES_{K_enc}(blk || ctr || "CTRK" || "VTF3"),  ct = pt ^ keystream
//   mac       = CMAC_{K_mac}(ct || blk || ctr || "DMAC" || "VTF3")
//   leaf      = ctr || blk || "CTR0" || "LEAF",  node = CMAC_{K_tree}(left || right)
//   root      kept in the trusted engine only (key tier).
// The ext_* members model untrusted storage; tests tamper with them directly.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "aes_cmac.h"

namespace crypto3d {

enum class MitStatus : uint8_t { OK = 0, TAMPER = 1, EXHAUSTED = 2 };

class MemoryIntegrityTree {
public:
    struct Block { uint8_t b[16]; };

    explicit MemoryIntegrityTree(const uint32_t root_key[4], size_t blocks = 16)
        : ext_ct(blocks), ext_mac(blocks), ext_ctr(blocks, 0u), ext_node(blocks - 2),
          B_(blocks), D_(0) {
        while ((size_t(1) << D_) < B_) ++D_;
        deriveKey(root_key, "VTFMEMENCKEY", k_enc_);
        deriveKey(root_key, "VTFMEMMACKEY", k_mac_);
        deriveKey(root_key, "VTFMEMTREEKY", k_tree_);
        for (auto& x : ext_ct) std::memset(x.b, 0, 16);
        for (auto& x : ext_mac) std::memset(x.b, 0, 16);
        build();
    }

    MitStatus read(size_t blk, uint8_t out[16]) {
        std::memset(out, 0, 16);
        const Block ct = ext_ct[blk], mac = ext_mac[blk];
        const uint32_t ctr = ext_ctr[blk];
        Block r, sibs[32];
        path(blk, ctr, nullptr, sibs, r, nullptr);
        if (!equal(r, root_)) { tamper_ = true; return MitStatus::TAMPER; }
        if (ctr == 0u) return MitStatus::OK;
        Block m = dataMac(blk, ctr, ct);
        if (!equal(m, mac)) { tamper_ = true; return MitStatus::TAMPER; }
        Block ks = keystream(blk, ctr);
        for (int i = 0; i < 16; ++i) out[i] = uint8_t(ct.b[i] ^ ks.b[i]);
        return MitStatus::OK;
    }

    MitStatus write(size_t blk, const uint8_t pt[16]) {
        const uint32_t old = ext_ctr[blk];
        Block r, sibs[32], nodes[32];
        path(blk, old, nullptr, sibs, r, nullptr);
        if (!equal(r, root_)) { tamper_ = true; return MitStatus::TAMPER; }
        if (old == 0xFFFFFFFFu) return MitStatus::EXHAUSTED;
        const uint32_t ctr = old + 1u;
        Block ks = keystream(blk, ctr), ct;
        for (int i = 0; i < 16; ++i) ct.b[i] = uint8_t(pt[i] ^ ks.b[i]);
        Block mac = dataMac(blk, ctr, ct);
        Block new_root;
        path(blk, ctr, sibs, sibs, new_root, nodes);   // reuse verified siblings (no TOCTOU)
        size_t idx = blk;
        for (size_t level = 1; level < D_; ++level) {
            idx >>= 1;
            ext_node[off(level) + idx] = nodes[level - 1];
        }
        ext_ct[blk] = ct; ext_mac[blk] = mac; ext_ctr[blk] = ctr;
        root_ = new_root;
        return MitStatus::OK;
    }

    void rootWords(uint32_t out[4]) const { cmac_bytes_to_words(root_.b, out); }
    bool tamperDetected() const { return tamper_; }

    // Untrusted storage (attacker-controlled in tests).
    std::vector<Block> ext_ct, ext_mac;
    std::vector<uint32_t> ext_ctr;
    std::vector<Block> ext_node;

private:
    size_t B_, D_;
    uint32_t k_enc_[4], k_mac_[4], k_tree_[4];
    Block root_{};
    bool tamper_ = false;

    static void deriveKey(const uint32_t root[4], const char label[13], uint32_t out[4]) {
        uint8_t in[16], o[16];
        std::memcpy(in, label, 12);
        in[12] = 0; in[13] = 0; in[14] = 0; in[15] = 1;
        cmac_aes_block(in, root, o);
        cmac_bytes_to_words(o, out);
    }
    static void put32(uint8_t* p, uint32_t x) { cmac_store_be32(p, x); }
    static bool equal(const Block& a, const Block& b) {
        uint8_t d = 0;
        for (int i = 0; i < 16; ++i) d |= uint8_t(a.b[i] ^ b.b[i]);
        return d == 0;
    }
    size_t off(size_t level) const { return B_ - (B_ >> (level - 1)); }

    static Block leaf(size_t i, uint32_t ctr) {
        Block l;
        put32(l.b, ctr); put32(l.b + 4, uint32_t(i));
        std::memcpy(l.b + 8, "CTR0LEAF", 8);
        return l;
    }
    Block cmac2(const uint32_t key[4], const Block& a, const Block& b) const {
        uint8_t msg[32];
        std::memcpy(msg, a.b, 16); std::memcpy(msg + 16, b.b, 16);
        uint32_t t[4]; Block o;
        aes_cmac_128(key, msg, 32, t);
        cmac_words_to_bytes(t, o.b);
        return o;
    }
    Block keystream(size_t blk, uint32_t ctr) const {
        uint8_t in[16]; Block o;
        put32(in, uint32_t(blk)); put32(in + 4, ctr);
        std::memcpy(in + 8, "CTRKVTF3", 8);
        cmac_aes_block(in, k_enc_, o.b);
        return o;
    }
    Block dataMac(size_t blk, uint32_t ctr, const Block& ct) const {
        Block tail;
        put32(tail.b, uint32_t(blk)); put32(tail.b + 4, ctr);
        std::memcpy(tail.b + 8, "DMACVTF3", 8);
        return cmac2(k_mac_, ct, tail);
    }
    void build() {
        std::vector<Block> prev(B_);
        for (size_t i = 0; i < B_; ++i) prev[i] = leaf(i, ext_ctr[i]);
        for (size_t level = 1; level <= D_; ++level) {
            std::vector<Block> cur(prev.size() / 2);
            for (size_t j = 0; j < cur.size(); ++j) {
                cur[j] = cmac2(k_tree_, prev[2 * j], prev[2 * j + 1]);
                if (level < D_) ext_node[off(level) + j] = cur[j];
            }
            prev.swap(cur);
        }
        root_ = prev[0];
    }
    // Recompute the root along blk's path. If use_sibs is given, siblings come from it
    // (trusted cache); otherwise from untrusted storage and are returned in got_sibs.
    void path(size_t blk, uint32_t ctr, const Block* use_sibs, Block* got_sibs,
              Block& out_root, Block* nodes) const {
        Block h = leaf(blk, ctr);
        size_t idx = blk;
        for (size_t level = 0; level < D_; ++level) {
            Block sib;
            if (use_sibs) sib = use_sibs[level];
            else if (level == 0) sib = leaf(idx ^ 1u, ext_ctr[idx ^ 1u]);
            else sib = ext_node[off(level) + (idx ^ 1u)];
            if (got_sibs && !use_sibs) got_sibs[level] = sib;
            h = (idx & 1u) ? cmac2(k_tree_, sib, h) : cmac2(k_tree_, h, sib);
            if (nodes) nodes[level] = h;
            idx >>= 1;
        }
        out_root = h;
    }
};

}  // namespace crypto3d
