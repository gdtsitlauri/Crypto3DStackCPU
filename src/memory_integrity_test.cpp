// Memory encryption + integrity tree (roadmap 2.1): C++ model vs the
// independent Python reference vectors (src/mit_vectors.h), plus attacks on
// the untrusted storage.
#include <cstdint>
#include <cstring>
#include <iostream>

#include "memory_integrity.h"
#include "mit_vectors.h"

using namespace crypto3d;

static bool expect(bool cond, const char* name) {
    std::cout << (cond ? "[PASS] " : "[FAIL] ") << name << "\n";
    return cond;
}

static bool eq4(const uint32_t a[4], const uint32_t b[4]) {
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

static void w2b(const uint32_t w[4], uint8_t b[16]) { cmac_words_to_bytes(w, b); }

static const uint32_t ROOT_KEY[4] = {0x2B7E1516u, 0x28AED2A6u, 0xABF71588u, 0x09CF4F3Cu};

static MemoryIntegrityTree scripted(bool& roots_ok) {
    MemoryIntegrityTree m(ROOT_KEY);
    roots_ok = true;
    for (int k = 0; k < 4; ++k) {
        uint8_t pt[16];
        w2b(mit_vectors::SCRIPT_PT[k], pt);
        roots_ok &= m.write(mit_vectors::SCRIPT_BLK[k], pt) == MitStatus::OK;
        uint32_t r[4];
        m.rootWords(r);
        roots_ok &= eq4(r, mit_vectors::SCRIPT_ROOT[k]);
    }
    return m;
}

int main() {
    std::cout << "== memory integrity tree (C++ model)\n";
    bool ok = true;
    {
        MemoryIntegrityTree m(ROOT_KEY);
        uint32_t r[4];
        m.rootWords(r);
        ok &= expect(eq4(r, mit_vectors::ROOT_INIT), "initial root matches Python reference");
    }
    bool roots_ok = false;
    MemoryIntegrityTree m = scripted(roots_ok);
    ok &= expect(roots_ok, "root after each scripted write matches Python reference");
    uint8_t ct2[16], mac2[16];
    w2b(mit_vectors::CT2, ct2);
    w2b(mit_vectors::MAC2, mac2);
    ok &= expect(std::memcmp(m.ext_ct[2].b, ct2, 16) == 0 && std::memcmp(m.ext_mac[2].b, mac2, 16) == 0,
                 "stored ciphertext and MAC of block 2 match Python reference");
    uint8_t out[16], exp[16];
    w2b(mit_vectors::SCRIPT_PT[2], exp);
    ok &= expect(m.read(2, out) == MitStatus::OK && std::memcmp(out, exp, 16) == 0, "read returns latest plaintext");
    ok &= expect(m.read(0, out) == MitStatus::OK && out[0] == 0, "never-written block reads as zero");

    auto attack = [&](const char* name, auto&& fn, size_t target) {
        bool r_ok = false;
        MemoryIntegrityTree a = scripted(r_ok);
        fn(a);
        uint8_t o[16];
        ok &= expect(a.read(target, o) == MitStatus::TAMPER && a.tamperDetected(), name);
    };
    attack("ciphertext bit flip detected", [](MemoryIntegrityTree& a) { a.ext_ct[5].b[0] ^= 1; }, 5);
    attack("data MAC bit flip detected", [](MemoryIntegrityTree& a) { a.ext_mac[5].b[9] ^= 0x40; }, 5);
    attack("splicing (ct+mac+ctr of another block) detected", [](MemoryIntegrityTree& a) {
        a.ext_ct[15] = a.ext_ct[5]; a.ext_mac[15] = a.ext_mac[5]; a.ext_ctr[15] = a.ext_ctr[5];
    }, 15);
    attack("counter rollback detected", [](MemoryIntegrityTree& a) { a.ext_ctr[2] = 1; }, 2);
    attack("full replay of an old snapshot detected", [](MemoryIntegrityTree& a) {
        auto ct = a.ext_ct[2]; auto mac = a.ext_mac[2]; auto c = a.ext_ctr[2]; auto nodes = a.ext_node;
        uint8_t z[16] = {0};
        a.write(2, z);
        a.ext_ct[2] = ct; a.ext_mac[2] = mac; a.ext_ctr[2] = c; a.ext_node = nodes;
    }, 2);
    {
        bool r_ok = false;
        MemoryIntegrityTree a = scripted(r_ok);
        a.ext_node[9].b[15] ^= 1;
        auto before = a.ext_ct[2];
        uint8_t z[16] = {1};
        ok &= expect(a.write(2, z) == MitStatus::TAMPER && std::memcmp(a.ext_ct[2].b, before.b, 16) == 0,
                     "tampered tree node blocks a write (nothing committed)");
    }
    if (!ok) { std::cout << "[MIT MODEL TEST FAIL]\n"; return 1; }
    std::cout << "[MIT MODEL TEST PASS]\n";
    return 0;
}
