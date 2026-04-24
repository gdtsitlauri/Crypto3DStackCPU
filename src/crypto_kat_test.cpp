#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>

#include "header.h"

namespace {

static void zeroize(uint32_t* p, int n) {
    volatile uint32_t* v = p;
    for (int i = 0; i < n; ++i) v[i] = 0u;
}

static bool equal4(const uint32_t a[4], const uint32_t b[4]) {
    uint32_t diff = 0u;
    for (int i = 0; i < 4; ++i) {
        diff |= (a[i] ^ b[i]);
    }
    return diff == 0u;
}

static void print4(const char* label, const uint32_t x[4]) {
    std::cout << label;
    for (int i = 0; i < 4; ++i) {
        std::cout << (i ? " " : "")
                  << "0x" << std::hex << std::uppercase
                  << std::setw(8) << std::setfill('0') << x[i]
                  << std::dec << std::nouppercase;
    }
    std::cout << "\n";
}

static bool aes_128_fips197_kat() {
    // FIPS-197 Appendix C.1:
    // Key:       000102030405060708090A0B0C0D0E0F
    // Plaintext: 00112233445566778899AABBCCDDEEFF
    // Cipher:    69C4E0D86A7B0430D8CDB78070B4C55A
    uint32_t key[4] = {
        0x00010203u, 0x04050607u, 0x08090A0Bu, 0x0C0D0E0Fu
    };

    uint32_t plain[4] = {
        0x00112233u, 0x44556677u, 0x8899AABBu, 0xCCDDEEFFu
    };

    const uint32_t expected_cipher[4] = {
        0x69C4E0D8u, 0x6A7B0430u, 0xD8CDB780u, 0x70B4C55Au
    };

    uint32_t cipher[4] = {0u, 0u, 0u, 0u};
    uint32_t roundtrip[4] = {0u, 0u, 0u, 0u};

    aes_encrypt_block(plain, key, cipher);
    if (!equal4(cipher, expected_cipher)) {
        print4("[DEBUG] AES encrypt got: ", cipher);
        print4("[DEBUG] AES encrypt exp: ", expected_cipher);
        zeroize(key, 4);
        zeroize(plain, 4);
        zeroize(cipher, 4);
        zeroize(roundtrip, 4);
        return false;
    }

    aes_decrypt_block(cipher, key, roundtrip);
    if (!equal4(roundtrip, plain)) {
        print4("[DEBUG] AES decrypt got: ", roundtrip);
        print4("[DEBUG] AES decrypt exp: ", plain);
        zeroize(key, 4);
        zeroize(plain, 4);
        zeroize(cipher, 4);
        zeroize(roundtrip, 4);
        return false;
    }

    zeroize(key, 4);
    zeroize(plain, 4);
    zeroize(cipher, 4);
    zeroize(roundtrip, 4);
    return true;
}

} // namespace

int main() {
    std::cout << "============================================================\n";
    std::cout << " Crypto3DStackCPU cryptographic known-answer tests\n";
    std::cout << "============================================================\n";

    bool ok = true;

    if (aes_128_fips197_kat()) {
        std::cout << "[PASS] AES-128 FIPS-197 encrypt/decrypt KAT\n";
    } else {
        std::cout << "[FAIL] AES-128 FIPS-197 encrypt/decrypt KAT\n";
        ok = false;
    }

    if (!ok) {
        std::cout << "[KAT FAIL]\n";
        return 1;
    }

    std::cout << "[KAT PASS] Cryptographic KAT suite passed.\n";
    return 0;
}
