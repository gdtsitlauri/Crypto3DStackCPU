#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>

#include "3d.h"
#include "vertical_trust_fabric.h"

using namespace crypto3d;

int main(int argc, char** argv) {
    uint32_t iterations = 100000u;
    if (argc > 1) {
        unsigned long v = std::strtoul(argv[1], nullptr, 10);
        if (v > 0 && v <= 5000000ul) iterations = (uint32_t)v;
    }

    StackedMemory3D mem(4, 1024);
    for (uint32_t i = 0; i < 1024; ++i) mem.write(1, i, i ^ 0xA5A5A5A5u);

    volatile uint32_t sink = 0u;
    auto t0 = std::chrono::steady_clock::now();
    for (uint32_t i = 0; i < iterations; ++i) {
        sink ^= mem.read(1, i & 1023u);
    }
    auto t1 = std::chrono::steady_clock::now();

    VerticalTrustFabric vtf(mem);
    VtfResponse rsp{};
    auto t2 = std::chrono::steady_clock::now();
    for (uint32_t i = 0; i < iterations; ++i) {
        auto req = vtf.issueRead(VtfRequester::CPU_DATA, 1, i & 1023u);
        if (!vtf.execute(req, rsp) || !vtf.verifyResponseForRequest(req, rsp)) {
            std::cerr << "VTF benchmark transaction failed at " << i << "\n";
            return 2;
        }
        sink ^= rsp.data;
    }
    auto t3 = std::chrono::steady_clock::now();

    const double baseline_ns = std::chrono::duration<double, std::nano>(t1 - t0).count() / iterations;
    const double vtf_ns = std::chrono::duration<double, std::nano>(t3 - t2).count() / iterations;
    const double ratio = baseline_ns > 0.0 ? vtf_ns / baseline_ns : 0.0;

    std::cout << std::fixed << std::setprecision(2);
    std::cout << "iterations=" << iterations << "\n";
    std::cout << "baseline_read_ns=" << baseline_ns << "\n";
    std::cout << "vtf_authenticated_read_ns=" << vtf_ns << "\n";
    std::cout << "host_overhead_ratio=" << ratio << "\n";
    std::cout << "accepted=" << vtf.counters().accepted << "\n";
    std::cout << "sink=" << sink << "\n";
    std::cout << "NOTE=Host software microbenchmark only; not FPGA/ASIC latency.\n";
    return 0;
}
