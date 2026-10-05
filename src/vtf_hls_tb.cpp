// C-simulation testbench for the HLS AES-CMAC authenticator (vtf_hls.cpp).
//
// Used by hardware_3d/scripts/vitis_hls_vtf_cmac.tcl (csim_design / cosim_design)
// and buildable natively. Expected tags are independent reference values
// computed with the Python `cryptography` package (AES-CMAC, SP 800-38B), whose
// output was itself checked against NIST SP 800-38B Example 2. Key and message
// words are big-endian, matching vertical_trust_fabric_test.cpp.
// Returns 0 on success, as required by Vitis HLS csim/cosim.

#include <cstdint>
#include <cstdio>

#include "vtf_hls.h"

namespace {

struct Vector {
    const char* name;
    uint32_t key[4];
    uint32_t msg[8];
    uint32_t tag[4];
};

const Vector kVectors[] = {
    {"nist_key_nist_msg32", {0x2b7e1516u, 0x28aed2a6u, 0xabf71588u, 0x09cf4f3cu},
     {0x6bc1bee2u, 0x2e409f96u, 0xe93d7e11u, 0x7393172au, 0xae2d8a57u, 0x1e03ac9cu, 0x9eb76facu, 0x45af8e51u},
     {0xce0cbf17u, 0x38f4df64u, 0x28b1d93bu, 0xf12081c9u}},
    {"zero_key_zero_msg", {0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u},
     {0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u},
     {0x3437d43au, 0x23ac3ce2u, 0x025ceaf9u, 0xc237ab53u}},
    {"vtf_transaction", {0x00010203u, 0x04050607u, 0x08090a0bu, 0x0c0d0e0fu},
     {0x00000001u, 0x00000002u, 0xc3d00005u, 0x00000001u, 0x00000007u, 0x00000009u, 0xdeadbeefu, 0xa5a5a5a5u},
     {0x9b44fbf8u, 0xf1137357u, 0xe8e1c6b6u, 0xd384a8bau}},
};

}  // namespace

int main() {
    int failures = 0;
    for (const Vector& v : kVectors) {
        uint32_t tag[4] = {0, 0, 0, 0};
        crypto3d_vtf_cmac_tag(v.msg, v.key, tag);
        bool tag_ok = true;
        for (int i = 0; i < 4; ++i) tag_ok = tag_ok && (tag[i] == v.tag[i]);

        const bool verify_ok = crypto3d_vtf_cmac_verify(v.msg, v.key, v.tag) == 1;

        // Any single-bit change of message, key or tag must be rejected.
        bool reject_ok = true;
        for (int bit = 0; bit < 32; bit += 7) {
            uint32_t msg[8], key[4], bad_tag[4];
            for (int i = 0; i < 8; ++i) msg[i] = v.msg[i];
            for (int i = 0; i < 4; ++i) { key[i] = v.key[i]; bad_tag[i] = v.tag[i]; }
            msg[bit % 8] ^= (1u << bit);
            reject_ok = reject_ok && crypto3d_vtf_cmac_verify(msg, v.key, v.tag) == 0;
            key[bit % 4] ^= (1u << bit);
            reject_ok = reject_ok && crypto3d_vtf_cmac_verify(v.msg, key, v.tag) == 0;
            bad_tag[bit % 4] ^= (1u << bit);
            reject_ok = reject_ok && crypto3d_vtf_cmac_verify(v.msg, v.key, bad_tag) == 0;
        }

        const bool ok = tag_ok && verify_ok && reject_ok;
        std::printf("[%s] %s tag=%08x%08x%08x%08x verify=%d reject=%d\n", ok ? "PASS" : "FAIL",
                    v.name, tag[0], tag[1], tag[2], tag[3], verify_ok, reject_ok);
        if (!ok) ++failures;
    }
    std::printf(failures == 0 ? "[HLS CSIM PASS] vtf_hls_tb\n" : "[HLS CSIM FAIL] vtf_hls_tb\n");
    return failures == 0 ? 0 : 1;
}
