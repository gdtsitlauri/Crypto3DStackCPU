#include <cstdint>
#include <iomanip>
#include <iostream>

#include "3d.h"
#include "header.h"

static bool expect(bool cond, const char* name) {
    if (cond) {
        std::cout << "[PASS] " << name << "\n";
        return true;
    }
    std::cout << "[FAIL] " << name << "\n";
    return false;
}

int main() {
    std::cout << "============================================================\n";
    std::cout << " Crypto3DStackCPU multi-layer memory abstraction test\n";
    std::cout << "============================================================\n";

    bool ok = true;

    StackedMemory3D mem(4, 64);

    ok &= expect(mem.getNumLayers() == 4, "four layers are available");
    ok &= expect(mem.getNumWords() == 64, "64 words per layer");

    mem.write(0, 0, 0x11111111u);
    mem.write(1, 0, 0x22222222u);
    mem.write(2, 0, 0x33333333u);
    mem.write(3, 0, 0x44444444u);

    ok &= expect(mem.read(0, 0) == 0x11111111u, "layer 0 independent read");
    ok &= expect(mem.read(1, 0) == 0x22222222u, "layer 1 independent read");
    ok &= expect(mem.read(2, 0) == 0x33333333u, "layer 2 independent read");
    ok &= expect(mem.read(3, 0) == 0x44444444u, "layer 3 independent read");

    mem.copyLayer(1, 2);
    ok &= expect(mem.read(2, 0) == 0x22222222u, "copyLayer copies source to destination");

    mem.setLayerAccess(1, false);
    ok &= expect(mem.read(1, 0) == 0xFFFFFFFFu, "access-disabled layer read is blocked");
    mem.setLayerAccess(1, true);
    ok &= expect(mem.read(1, 0) == 0x22222222u, "access-restored layer read succeeds");

    mem.write(3, 4, 0xCAFEBABEu);
    mem.encryptLayer(3);
    ok &= expect(mem.rawRead(3, 4) != 0xCAFEBABEu, "encrypted layer rawRead hides plaintext");
    ok &= expect(mem.read(3, 4) == 0xCAFEBABEu, "encrypted layer logical read decrypts plaintext");
    mem.decryptLayer(3);
    ok &= expect(mem.read(3, 4) == 0xCAFEBABEu, "decryptLayer restores logical plaintext");

    size_t secret_bits[128];
    for (size_t i = 0; i < 128; ++i) {
        secret_bits[i] = i;
    }

    uint32_t key_in[4] = {
        0xCAFEBABEu, 0xAABBCCDDu, 0x11223344u, 0x55667788u
    };
    uint32_t key_out[4] = {0u, 0u, 0u, 0u};

    mem.hideKeyInLayer(2, key_in, 4, secret_bits, 128);
    mem.extractKeyFromLayer(2, secret_bits, 128, key_out, 4);

    bool key_ok = true;
    for (int i = 0; i < 4; ++i) {
        key_ok &= (key_in[i] == key_out[i]);
    }
    ok &= expect(key_ok, "per-layer key hide/extract works");

    mem.enableProcessingLayer(2);
    mem.protectedRead(2, 0);
    ok &= expect(mem.isProcessingLayerEnabled(), "processing layer can be enabled on nonzero layer");
    mem.clearProcessingLayer();
    ok &= expect(!mem.isProcessingLayerEnabled(), "processing layer can be cleared");

    StackedMemory3D::TamperPoint tp = {0, 0, 0x11111111u};
    mem.checkMultipleTamper(&tp, 1);
    ok &= expect(!mem.isSecurityLocked(), "correct tamper point does not lock security");

    mem.write(0, 0, 0xAAAAAAAAu);
    mem.checkTamper(0, 0, 0x11111111u);
    ok &= expect(mem.isSecurityLocked(), "wrong tamper point locks security");

    if (!ok) {
        std::cout << "[MULTILAYER TEST FAIL]\n";
        return 1;
    }

    std::cout << "[MULTILAYER TEST PASS]\n";
    return 0;
}
