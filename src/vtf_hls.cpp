#include "vtf_hls.h"
#include "aes_cmac.h"

extern "C" void crypto3d_vtf_cmac_tag(const uint32_t message_words[8],
                                      const uint32_t key_words[4],
                                      uint32_t tag_out[4]) {
#pragma HLS INTERFACE ap_memory port=message_words
#pragma HLS INTERFACE ap_memory port=key_words
#pragma HLS INTERFACE ap_memory port=tag_out
#pragma HLS INTERFACE ap_ctrl_hs port=return
    uint8_t msg[32];
#pragma HLS ARRAY_PARTITION variable=msg complete dim=1
    for (int i = 0; i < 8; ++i) {
#pragma HLS UNROLL
        crypto3d::cmac_store_be32(&msg[i * 4], message_words[i]);
    }
    crypto3d::aes_cmac_128(key_words, msg, 32u, tag_out);
}

extern "C" int crypto3d_vtf_cmac_verify(const uint32_t message_words[8],
                                         const uint32_t key_words[4],
                                         const uint32_t expected_tag[4]) {
#pragma HLS INTERFACE ap_memory port=message_words
#pragma HLS INTERFACE ap_memory port=key_words
#pragma HLS INTERFACE ap_memory port=expected_tag
#pragma HLS INTERFACE ap_ctrl_hs port=return
    uint32_t got[4];
#pragma HLS ARRAY_PARTITION variable=got complete dim=1
    crypto3d_vtf_cmac_tag(message_words, key_words, got);
    return crypto3d::cmac_tag_equal(got, expected_tag) ? 1 : 0;
}
