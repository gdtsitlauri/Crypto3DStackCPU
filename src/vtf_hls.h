#ifndef CRYPTO3D_VTF_HLS_H
#define CRYPTO3D_VTF_HLS_H

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// HLS-facing AES-CMAC transaction authenticator. The 8 message words are
// interpreted as 32 big-endian bytes; tag_out contains four 32-bit words.
void crypto3d_vtf_cmac_tag(const uint32_t message_words[8],
                           const uint32_t key_words[4],
                           uint32_t tag_out[4]);

int crypto3d_vtf_cmac_verify(const uint32_t message_words[8],
                             const uint32_t key_words[4],
                             const uint32_t expected_tag[4]);

#ifdef __cplusplus
}
#endif

#endif
