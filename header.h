#ifndef HEADER_H
#define HEADER_H

#include <cstdint>

// ------------------------------------------------------------------------
// Global parameters (kept consistent with 3d.h / 3d.cpp)
// ------------------------------------------------------------------------
#define MEM_SIZE          1024   // same as 3d.h
#define INSTRS_PER_BLOCK  4      // block = 4 words

// ------------------------------------------------------------------------
// Secure image header layout (word offsets in layer 0)
// ------------------------------------------------------------------------
#define SEC_HDR_MAGIC          0x33444352u  // "3DCR"
#define SEC_HDR_VERSION        0x00020000u
#define SEC_HDR_FLAGS          0x0000000Fu  // bit0: single-layer, bit1: wrapped-key, bit2: hkdf, bit3: mapped-text

#define SEC_POLICY_MAP_ENABLED     0x00000001u
#define SEC_POLICY_STRICT_TAMPER   0x00000002u
#define SEC_POLICY_RESEAL_READY    0x00000004u

#define SEC_DATA_FLAG_ENCRYPTED    0x00000001u

#define SEC_HDR_W_MAGIC        0u
#define SEC_HDR_W_VERSION      1u
#define SEC_HDR_W_FLAGS        2u
#define SEC_HDR_W_POLICY       3u
#define SEC_HDR_W_TEXT_START   4u
#define SEC_HDR_W_TEXT_WORDS   5u
#define SEC_HDR_W_TEXT_END     6u
#define SEC_HDR_W_EPOCH        7u
#define SEC_HDR_W_NONCE0       8u
#define SEC_HDR_W_NONCE1       9u
#define SEC_HDR_W_NONCE2       10u
#define SEC_HDR_W_NONCE3       11u
#define SEC_HDR_W_WRAP0        12u
#define SEC_HDR_W_WRAP1        13u
#define SEC_HDR_W_WRAP2        14u
#define SEC_HDR_W_WRAP3        15u
#define SEC_HDR_W_KEYTAG0      16u
#define SEC_HDR_W_KEYTAG1      17u
#define SEC_HDR_W_KEYTAG2      18u
#define SEC_HDR_W_KEYTAG3      19u
#define SEC_HDR_W_IMGTAG0      20u
#define SEC_HDR_W_IMGTAG1      21u
#define SEC_HDR_W_IMGTAG2      22u
#define SEC_HDR_W_IMGTAG3      23u
#define SEC_HDR_W_MEAS0        24u
#define SEC_HDR_W_MEAS1        25u
#define SEC_HDR_W_MEAS2        26u
#define SEC_HDR_W_MEAS3        27u
#define SEC_HDR_W_DATA_START   28u
#define SEC_HDR_W_DATA_WORDS   29u
#define SEC_HDR_W_DATA_END     30u
#define SEC_HDR_W_DATA_FLAGS   31u
#define SEC_HDR_WORDS          32u

#ifdef __cplusplus
extern "C" {
#endif

// ------------------------------------------------------------------------
// Extern "C" functions implemented in 3d.cpp
// ------------------------------------------------------------------------

// Creates block-0 secure header + wrapped key (used by encryptor).
int create_large_block_with_key(uint32_t layer, uint32_t key[4]);

// Extracts app key from block 0 (used by CPU fetch stage).
int extract_key_from_large_block(uint32_t layer, uint32_t key[4]);

// Configure secure image metadata before key-wrapping/hiding.
void secure_set_image_region(uint32_t text_start_addr, uint32_t text_plain_words, uint32_t text_enc_end);

// Configure secure data metadata (encrypted data region).
void secure_set_data_region(uint32_t data_start_addr, uint32_t data_plain_words, uint32_t data_enc_end, uint32_t data_flags);

// Configure mapping epoch (same image can be resealed with different epoch).
void secure_set_mapping_epoch(uint32_t epoch);

// Map logical text block address to physical address (based on secure header policy).
uint32_t secure_map_text_block(uint32_t logical_block_addr);

// Read secure image metadata parsed from header.
int secure_get_image_region(uint32_t *text_start_addr,
                            uint32_t *text_plain_words,
                            uint32_t *text_enc_end,
                            uint32_t *epoch);

// Read secure data metadata parsed from header.
int secure_get_data_region(uint32_t *data_start_addr,
                           uint32_t *data_plain_words,
                           uint32_t *data_enc_end,
                           uint32_t *data_flags);

// Verify secure image metadata and authenticated text region.
int secure_validate_image(uint32_t layer);

// Decrypt and read one data word in plaintext using wrapped app key.
int secure_read_data_word_plain(uint32_t word_addr, uint32_t *plain_value);

// AES block primitives.
void aes_encrypt_block(uint32_t in[4], uint32_t key[4], uint32_t out[4]);
void aes_decrypt_block(uint32_t in[4], uint32_t key[4], uint32_t out[4]);

#ifdef __cplusplus
}
#endif

#endif // HEADER_H
