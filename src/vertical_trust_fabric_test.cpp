#include <cstdint>
#include <iomanip>
#include <iostream>

#include "3d.h"
#include "aes_cmac.h"
#include "vertical_trust_fabric.h"
#include "vtf_hls.h"

using namespace crypto3d;

static bool expect(bool cond, const char* name) {
    std::cout << (cond ? "[PASS] " : "[FAIL] ") << name << "\n";
    return cond;
}

static bool equal4(const uint32_t a[4], const uint32_t b[4]) {
    uint32_t d = 0u;
    for (int i = 0; i < 4; ++i) d |= (a[i] ^ b[i]);
    return d == 0u;
}

static bool cmac_kat() {
    // NIST SP 800-38B AES-CMAC Example 2 (one complete block)
    uint32_t key[4] = {0x2B7E1516u,0x28AED2A6u,0xABF71588u,0x09CF4F3Cu};
    uint8_t msg[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    const uint32_t expected[4] = {0x070A16B4u,0x6B4D4144u,0xF79BDD9Du,0xD04A287Cu};
    uint32_t tag[4];
    aes_cmac_128(key, msg, sizeof(msg), tag);
    return equal4(tag, expected);
}

int main() {
    std::cout << "============================================================\n";
    std::cout << " Crypto3DStackCPU Vertical Trust Fabric validation\n";
    std::cout << "============================================================\n";
    bool ok = true;

    ok &= expect(cmac_kat(), "AES-CMAC NIST SP 800-38B known-answer test");

    // Validate HLS wrapper against the same CMAC implementation.
    uint32_t hls_msg[8] = {0x00010203u,0x04050607u,0x08090A0Bu,0x0C0D0E0Fu,
                           0x10111213u,0x14151617u,0x18191A1Bu,0x1C1D1E1Fu};
    uint32_t hls_key[4] = {0x2B7E1516u,0x28AED2A6u,0xABF71588u,0x09CF4F3Cu};
    uint32_t hls_tag[4] = {0,0,0,0};
    crypto3d_vtf_cmac_tag(hls_msg, hls_key, hls_tag);
    ok &= expect(crypto3d_vtf_cmac_verify(hls_msg, hls_key, hls_tag) == 1,
                 "HLS CMAC wrapper verifies its tag");
    uint32_t hls_bad[4] = {hls_tag[0] ^ 1u, hls_tag[1], hls_tag[2], hls_tag[3]};
    ok &= expect(crypto3d_vtf_cmac_verify(hls_msg, hls_key, hls_bad) == 0,
                 "HLS CMAC wrapper rejects modified tag");

    StackedMemory3D mem(4, 64);
    VerticalTrustFabric vtf(mem);
    vtf.setTierRole(0, VtfTierRole::INSTRUCTION);
    vtf.setTierRole(1, VtfTierRole::DATA);
    vtf.setTierRole(2, VtfTierRole::KEY_METADATA);
    vtf.setTierRole(3, VtfTierRole::SENTINEL);

    // Provision with SECURITY requester.
    VtfResponse rsp{};
    auto p0 = vtf.issueWrite(VtfRequester::SECURITY, 0, 3, 0x11223344u);
    ok &= expect(vtf.execute(p0, rsp) && vtf.verifyResponseForRequest(p0, rsp),
                 "security tier can provision instruction layer");
    auto p1 = vtf.issueWrite(VtfRequester::SECURITY, 1, 5, 0xAABBCCDDu);
    ok &= expect(vtf.execute(p1, rsp) && vtf.verifyResponseForRequest(p1, rsp),
                 "security tier can provision data layer");
    auto p2 = vtf.issueWrite(VtfRequester::SECURITY, 2, 7, 0x55AA55AAu);
    ok &= expect(vtf.execute(p2, rsp), "security tier can provision key/metadata layer");

    auto fetch = vtf.issueRead(VtfRequester::CPU_FETCH, 0, 3);
    ok &= expect(vtf.execute(fetch, rsp) && rsp.data == 0x11223344u && vtf.verifyResponseForRequest(fetch, rsp),
                 "CPU fetch can read instruction tier with authenticated response");

    auto data_r = vtf.issueRead(VtfRequester::CPU_DATA, 1, 5);
    ok &= expect(vtf.execute(data_r, rsp) && rsp.data == 0xAABBCCDDu,
                 "CPU data requester can read data tier");

    auto data_w = vtf.issueWrite(VtfRequester::CPU_DATA, 1, 6, 0xCAFEBABEu);
    ok &= expect(vtf.execute(data_w, rsp) && mem.read(1, 6) == 0xCAFEBABEu,
                 "CPU data requester can write data tier");

    auto key_denied = vtf.issueRead(VtfRequester::CPU_DATA, 2, 7);
    ok &= expect(!vtf.execute(key_denied, rsp) && !vtf.isLockedDown() &&
                 vtf.lastDenyReason() == VtfDenyReason::POLICY,
                 "CPU data requester is denied key tier without causing destructive lock");

    // Debug is off by default.
    auto dbg = vtf.issueRead(VtfRequester::DEBUG, 1, 5);
    ok &= expect(!vtf.execute(dbg, rsp), "debug requester denied while debug lock is closed");

    // Sentinel provisioning/verification.
    ok &= expect(vtf.installSentinels(), "sentinel canaries installed in sentinel tier");
    ok &= expect(vtf.verifySentinels(), "untampered sentinel canaries verify");

    // Test tag binding to the selected layer: modifying layer after signing must fail.
    vtf.resetProtocolStateForSimulation();
    auto signed_req = vtf.issueRead(VtfRequester::CPU_DATA, 1, 5);
    signed_req.layer = 2; // malicious TSV/layer-select alteration
    ok &= expect(!vtf.execute(signed_req, rsp) && vtf.isLockedDown() &&
                 vtf.lastDenyReason() == VtfDenyReason::BAD_TAG,
                 "layer spoofing after authentication is detected by CMAC binding");
    ok &= expect(mem.rawRead(2, 7) == 0u,
                 "severe authentication failure zeroizes key/metadata tier");

    // Replay rejection on a fresh memory/fabric instance.
    StackedMemory3D mem2(4, 64);
    VerticalTrustFabric replay_vtf(mem2);
    auto w2 = replay_vtf.issueWrite(VtfRequester::SECURITY, 1, 1, 0x12345678u);
    ok &= expect(replay_vtf.execute(w2, rsp), "fresh authenticated write accepted");
    ok &= expect(!replay_vtf.execute(w2, rsp) && replay_vtf.isLockedDown() &&
                 replay_vtf.lastDenyReason() == VtfDenyReason::REPLAY,
                 "replayed authenticated transaction is rejected and locks down");

    // Payload bit flip must invalidate the request tag.
    StackedMemory3D mem3(4, 64);
    VerticalTrustFabric flip_vtf(mem3);
    auto wf = flip_vtf.issueWrite(VtfRequester::CPU_DATA, 1, 2, 0x01020304u);
    wf.data ^= 0x00000001u;
    ok &= expect(!flip_vtf.execute(wf, rsp) && flip_vtf.lastDenyReason() == VtfDenyReason::BAD_TAG,
                 "TSV payload bit flip is detected by authenticated transaction tag");

    // Thermal trip modelling and critical tier zeroization.
    StackedMemory3D mem4(4, 64);
    VerticalTrustFabric thermal_vtf(mem4);
    auto wk = thermal_vtf.issueWrite(VtfRequester::SECURITY, 2, 4, 0xDEADBEEFu);
    ok &= expect(thermal_vtf.execute(wk, rsp), "key tier contains provisioned metadata before thermal trip");
    thermal_vtf.updateTemperatureMilliC(2, 95000);
    ok &= expect(thermal_vtf.isLockedDown() && thermal_vtf.lastDenyReason() == VtfDenyReason::THERMAL,
                 "over-temperature event trips vertical trust fabric");
    ok &= expect(mem4.read(2, 4) == 0xFFFFFFFFu && mem4.rawRead(2, 4) == 0u,
                 "thermal severe trip zeroizes and access-locks key tier");

    // Sentinel physical tamper modelling.
    StackedMemory3D mem5(4, 64);
    VerticalTrustFabric sentinel_vtf(mem5);
    ok &= expect(sentinel_vtf.installSentinels(), "second sentinel bank installed");
    mem5.memory[3][63] ^= 0x1u; // physical/raw fault bypassing normal write path
    ok &= expect(!sentinel_vtf.verifySentinels() && sentinel_vtf.isLockedDown() &&
                 sentinel_vtf.lastDenyReason() == VtfDenyReason::SENTINEL,
                 "physical sentinel corruption is detected and locks down");

    // Roadmap 1.3: epoch/role key hierarchy, cross-checked against the independent
    // Python reference (hardware_3d/scripts/vtf_reference.py -> hardware_3d/tb/vtf_vectors.svh)
    // and therefore against the RTL key schedule (hardware_3d/rtl/vtf_key_schedule.sv).
    {
        StackedMemory3D mem6(4, 64);
        VerticalTrustFabric ek_vtf(mem6);
        ek_vtf.setTierRole(0, VtfTierRole::INSTRUCTION);
        ek_vtf.setTierRole(1, VtfTierRole::DATA);
        ek_vtf.setTierRole(2, VtfTierRole::KEY_METADATA);
        const uint32_t root[4] = {0x2B7E1516u,0x28AED2A6u,0xABF71588u,0x09CF4F3Cu};
        ek_vtf.setRootKeyForSimulation(root);
        ek_vtf.setEpochKeyHierarchy(true);
        const uint32_t e1_req[5][4] = {
            {0xde3ebfd2u,0x5858a0fau,0x62c16947u,0x375e13eeu},
            {0xd6c84846u,0xe05ecdd3u,0x3826003bu,0x0fcb47bau},
            {0x715e91c6u,0x4b99a391u,0xde5ad185u,0xf045c9b9u},
            {0xd19a29bdu,0xbb5f00ceu,0xd2542fadu,0x66e2ac11u},
            {0x1224a153u,0x330b40ccu,0x32230e05u,0x58e5f36au}};
        const uint32_t e1_rsp[4] = {0x1d5c9d03u,0x15fb57c0u,0xdc9257e8u,0x686ee41du};
        const uint32_t e2_req[5][4] = {
            {0xaa873f46u,0x84dac5ffu,0x91b33c02u,0xca19feafu},
            {0x0bc3797eu,0x021bc7e7u,0x4bc01c13u,0x83a97e3bu},
            {0x29f41973u,0x4e773410u,0xe04c9f72u,0xfddae3e7u},
            {0xb79953b0u,0xd3bdfbb0u,0x38162d78u,0x06a95d9fu},
            {0x87de0329u,0x91a1ea64u,0x9f4b6065u,0xc4ff4e8du}};
        const uint32_t e2_rsp[4] = {0x820bb7edu,0x76a58001u,0xa5fad831u,0xc940e376u};
        bool keys_e1 = true;
        uint32_t k[4];
        for (int r = 0; r < 5; ++r) {
            ek_vtf.requestKeyForTest((VtfRequester)r, k);
            keys_e1 &= equal4(k, e1_req[r]);
        }
        ek_vtf.responseKeyForTest(k);
        keys_e1 &= equal4(k, e1_rsp);
        ok &= expect(keys_e1, "epoch-1 per-requester/response keys match Python reference and RTL vectors");

        auto ereq = ek_vtf.issueWrite(VtfRequester::SECURITY, 2, 0x10, 0xA5A55A5Au);
        const uint32_t ref_tag[4] = {0x81684c23u,0x85da05f4u,0x3335fcf1u,0x10b1c724u};
        ok &= expect(equal4(ereq.tag, ref_tag), "epoch-keyed request tag matches Python/RTL reference tag");
        VtfResponse ersp;
        ok &= expect(ek_vtf.execute(ereq, ersp) && ek_vtf.verifyResponseForRequest(ereq, ersp),
                     "epoch-keyed request accepted and response authenticated");

        uint32_t dma_key[4], sec_key[4];
        ek_vtf.requestKeyForTest(VtfRequester::DMA, dma_key);
        ek_vtf.requestKeyForTest(VtfRequester::SECURITY, sec_key);
        ok &= expect(!equal4(dma_key, sec_key), "requesters hold distinct epoch keys");

        ek_vtf.advanceEpoch();
        bool keys_e2 = true;
        for (int r = 0; r < 5; ++r) {
            ek_vtf.requestKeyForTest((VtfRequester)r, k);
            keys_e2 &= equal4(k, e2_req[r]);
        }
        ek_vtf.responseKeyForTest(k);
        keys_e2 &= equal4(k, e2_rsp);
        ok &= expect(keys_e2, "epoch advance re-derives keys equal to epoch-2 reference vectors");

        auto stale = ereq;                             // epoch-1 tag relabelled as epoch 2
        stale.epoch = 2u;
        stale.sequence = 1u;
        ok &= expect(!ek_vtf.execute(stale, ersp) && ek_vtf.lastDenyReason() == VtfDenyReason::BAD_TAG,
                     "epoch-1 tag forged into epoch 2 is rejected (forward key separation)");
    }

    if (!ok) {
        std::cout << "[VTF VALIDATION FAIL]\n";
        return 1;
    }

    std::cout << "[VTF VALIDATION PASS]\n";
    return 0;
}
