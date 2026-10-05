#include <cstdint>
#include <iostream>
#include "3d.h"

static bool expect(bool cond, const char* name) {
    std::cout << (cond ? "[PASS] " : "[FAIL] ") << name << "\n";
    return cond;
}

int main() {
    bool ok = true;
    StackedMemory3D a(4, 64);
    StackedMemory3D b(4, 64);

    const uint32_t root_a[4] = {0x00112233u,0x44556677u,0x8899AABBu,0xCCDDEEFFu};
    const uint32_t root_b[4] = {0x10213243u,0x54657687u,0x98A9BACBu,0xDCEDFE0Fu};
    a.setHardwareRootKey(root_a);
    b.setHardwareRootKey(root_b);

    uint32_t aw = a.deriveHardwareWord(0x12345678u, 0x31u);
    uint32_t bw = b.deriveHardwareWord(0x12345678u, 0x31u);
    ok &= expect(aw != bw, "different 128-bit device roots derive different hardware words");

    bool layer_keys_differ = false;
    for (int l = 0; l < 4; ++l) {
        for (int k = 0; k < 4; ++k) {
            layer_keys_differ |= (a.layer_keys[l][k] != b.layer_keys[l][k]);
        }
    }
    ok &= expect(layer_keys_differ, "different device roots derive different per-layer AES keys");

    StackedMemory3D c(4, 64);
    c.setHardwareRootKey(root_a);
    ok &= expect(a.deriveHardwareWord(0xCAFEBABEu, 0x44u) ==
                 c.deriveHardwareWord(0xCAFEBABEu, 0x44u),
                 "same provisioned root is deterministic across model instances");

    // Legacy 32-bit seed path remains deterministic but is explicitly only a
    // test/backward-compatibility mechanism.
    StackedMemory3D d(4, 64);
    StackedMemory3D e(4, 64);
    d.setHardwareKey(0x1234ABCDu);
    e.setHardwareKey(0x1234ABCDu);
    ok &= expect(d.deriveHardwareWord(7u, 9u) == e.deriveHardwareWord(7u, 9u),
                 "legacy seed API deterministically expands into a 128-bit simulation root");

    if (!ok) {
        std::cout << "[ROOT PROVISIONING TEST FAIL]\n";
        return 1;
    }
    std::cout << "[ROOT PROVISIONING TEST PASS]\n";
    return 0;
}
