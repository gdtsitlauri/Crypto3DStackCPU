#include <cstdint>
#include <iostream>
#include <string>

#include "3d.h"
#include "vertical_trust_fabric.h"

using namespace crypto3d;

static bool expect(bool cond, const std::string& name) {
    std::cout << (cond ? "[PASS] " : "[FAIL] ") << name << "\n";
    return cond;
}

template <typename Mutator>
static bool mutation_rejected(const char* name, Mutator mutate) {
    StackedMemory3D mem(4, 64);
    VerticalTrustFabric vtf(mem);
    VtfResponse rsp{};
    auto req = vtf.issueWrite(VtfRequester::CPU_DATA, 1, 9, 0x1234ABCDu);
    mutate(req);
    bool rejected = !vtf.execute(req, rsp);
    return expect(rejected, std::string("authenticated request mutation rejected: ") + name);
}

int main() {
    bool ok = true;

    ok &= mutation_rejected("requester", [](VtfRequest& r){ r.requester = VtfRequester::DMA; });
    ok &= mutation_rejected("operation", [](VtfRequest& r){ r.operation = VtfOperation::READ; });
    ok &= mutation_rejected("layer", [](VtfRequest& r){ r.layer = 0; });
    ok &= mutation_rejected("address", [](VtfRequest& r){ r.addr ^= 1u; });
    ok &= mutation_rejected("payload", [](VtfRequest& r){ r.data ^= 0x80000000u; });
    ok &= mutation_rejected("sequence", [](VtfRequest& r){ r.sequence += 1u; });
    ok &= mutation_rejected("epoch", [](VtfRequest& r){ r.epoch += 1u; });
    ok &= mutation_rejected("route nonce", [](VtfRequest& r){ r.route_nonce ^= 0x1u; });
    ok &= mutation_rejected("tag", [](VtfRequest& r){ r.tag[3] ^= 0x1u; });

    // Policy matrix sanity: all intended non-security requesters.
    {
        StackedMemory3D mem(4, 64);
        VerticalTrustFabric vtf(mem);
        VtfResponse rsp{};
        auto a = vtf.issueRead(VtfRequester::CPU_FETCH, 0, 0);
        ok &= expect(vtf.execute(a, rsp), "policy matrix allows CPU_FETCH -> instruction read");
        auto b = vtf.issueRead(VtfRequester::CPU_DATA, 1, 0);
        ok &= expect(vtf.execute(b, rsp), "policy matrix allows CPU_DATA -> data read");
        auto c = vtf.issueWrite(VtfRequester::DMA, 1, 0, 7);
        ok &= expect(vtf.execute(c, rsp), "policy matrix allows DMA -> data write");
        auto d = vtf.issueRead(VtfRequester::CPU_FETCH, 1, 0);
        ok &= expect(!vtf.execute(d, rsp) && !vtf.isLockedDown(),
                     "policy matrix safely denies CPU_FETCH -> data");
        auto e = vtf.issueRead(VtfRequester::CPU_FETCH, 0, 0);
        ok &= expect(vtf.execute(e, rsp),
                     "authenticated policy denial consumes sequence without desynchronizing requester");
    }


    // Response binding sanity: a valid response is bound to the originating request.
    {
        StackedMemory3D mem(4, 64);
        VerticalTrustFabric vtf(mem);
        VtfResponse rsp{};
        auto req1 = vtf.issueRead(VtfRequester::CPU_DATA, 1, 3);
        ok &= expect(vtf.execute(req1, rsp) && vtf.verifyResponseForRequest(req1, rsp),
                     "response authenticates and binds to originating request");
        VtfResponse tampered_rsp = rsp;
        tampered_rsp.addr ^= 1u;
        ok &= expect(!vtf.verifyResponseForRequest(req1, tampered_rsp),
                     "modified response is rejected");
        auto req2 = vtf.issueRead(VtfRequester::CPU_DATA, 1, 4);
        ok &= expect(!vtf.verifyResponseForRequest(req2, rsp),
                     "old valid response cannot satisfy a different request context");
    }

    if (!ok) {
        std::cout << "[VTF PROPERTY TEST FAIL]\n";
        return 1;
    }
    std::cout << "[VTF PROPERTY TEST PASS]\n";
    return 0;
}
