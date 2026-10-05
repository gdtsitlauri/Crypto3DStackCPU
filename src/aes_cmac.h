#ifndef CRYPTO3D_AES_CMAC_H
#define CRYPTO3D_AES_CMAC_H

#include <cstddef>
#include <cstdint>

#include "3d.h"

// AES-CMAC (NIST SP 800-38B) helper built on the repository's validated
// AES-128 primitive. The implementation is allocation-free and suitable for
// software/HLS experiments. It is not a substitute for side-channel-hardened
// hardware in a physical implementation.
namespace crypto3d {

static inline uint32_t cmac_load_be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           ((uint32_t)p[3]);
}

static inline void cmac_store_be32(uint8_t* p, uint32_t x) {
    p[0] = (uint8_t)((x >> 24) & 0xFFu);
    p[1] = (uint8_t)((x >> 16) & 0xFFu);
    p[2] = (uint8_t)((x >> 8) & 0xFFu);
    p[3] = (uint8_t)(x & 0xFFu);
}

static inline void cmac_words_to_bytes(const uint32_t in[4], uint8_t out[16]) {
    for (int i = 0; i < 4; ++i) cmac_store_be32(&out[i * 4], in[i]);
}

static inline void cmac_bytes_to_words(const uint8_t in[16], uint32_t out[4]) {
    for (int i = 0; i < 4; ++i) out[i] = cmac_load_be32(&in[i * 4]);
}

static inline void cmac_xor16(const uint8_t a[16], const uint8_t b[16], uint8_t out[16]) {
    for (int i = 0; i < 16; ++i) out[i] = (uint8_t)(a[i] ^ b[i]);
}

static inline void cmac_left_shift_128(const uint8_t in[16], uint8_t out[16]) {
    uint8_t carry = 0u;
    for (int i = 15; i >= 0; --i) {
        uint8_t next = (uint8_t)((in[i] >> 7) & 1u);
        out[i] = (uint8_t)((in[i] << 1) | carry);
        carry = next;
    }
}

static inline void cmac_aes_block(const uint8_t in[16], const uint32_t key[4], uint8_t out[16]) {
    uint32_t iw[4], ow[4];
    cmac_bytes_to_words(in, iw);
    uint32_t key_local[4] = {key[0], key[1], key[2], key[3]};
    aes_encrypt_block(iw, key_local, ow);
    cmac_words_to_bytes(ow, out);
}

static inline void aes_cmac_128(const uint32_t key[4],
                                const uint8_t* msg,
                                size_t len,
                                uint32_t tag[4]) {
    uint8_t zero[16] = {0};
    uint8_t L[16], K1[16], K2[16];
    cmac_aes_block(zero, key, L);

    const bool msb_l = (L[0] & 0x80u) != 0u;
    cmac_left_shift_128(L, K1);
    if (msb_l) K1[15] ^= 0x87u;

    const bool msb_k1 = (K1[0] & 0x80u) != 0u;
    cmac_left_shift_128(K1, K2);
    if (msb_k1) K2[15] ^= 0x87u;

    size_t n = (len + 15u) / 16u;
    bool complete = (len != 0u) && ((len % 16u) == 0u);
    if (n == 0u) n = 1u;

    uint8_t last[16] = {0};
    if (complete) {
        size_t off = (n - 1u) * 16u;
        for (int i = 0; i < 16; ++i) last[i] = (uint8_t)(msg[off + (size_t)i] ^ K1[i]);
    } else {
        size_t off = (n - 1u) * 16u;
        size_t rem = (len > off) ? (len - off) : 0u;
        for (size_t i = 0; i < rem; ++i) last[i] = msg[off + i];
        last[rem] = 0x80u;
        for (int i = 0; i < 16; ++i) last[i] ^= K2[i];
    }

    uint8_t X[16] = {0};
    uint8_t Y[16] = {0};
    uint8_t block[16] = {0};

    for (size_t b = 0; b + 1u < n; ++b) {
        size_t off = b * 16u;
        for (int i = 0; i < 16; ++i) block[i] = msg[off + (size_t)i];
        cmac_xor16(X, block, Y);
        cmac_aes_block(Y, key, X);
    }

    cmac_xor16(X, last, Y);
    cmac_aes_block(Y, key, X);
    cmac_bytes_to_words(X, tag);

    volatile uint8_t* wipe8[] = {L, K1, K2, last, X, Y, block};
    for (int a = 0; a < 7; ++a) {
        for (int i = 0; i < 16; ++i) wipe8[a][i] = 0u;
    }
}

static inline bool cmac_tag_equal(const uint32_t a[4], const uint32_t b[4]) {
    uint32_t diff = 0u;
    for (int i = 0; i < 4; ++i) diff |= (a[i] ^ b[i]);
    return diff == 0u;
}

} // namespace crypto3d

#endif
