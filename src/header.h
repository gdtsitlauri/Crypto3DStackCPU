#ifndef CRYPTO3D_HEADER_H
#define CRYPTO3D_HEADER_H

#include <cstdint>

// -----------------------------------------------------------------------------
// Shared architectural constants
// -----------------------------------------------------------------------------
// Keep these values synchronized with 3d.h / 3d.cpp.  The guards avoid noisy
// macro redefinition diagnostics when this header is included after 3d.h.
#ifndef MEM_SIZE
#define MEM_SIZE 1024u
#endif

#ifndef INSTRS_PER_BLOCK
#define INSTRS_PER_BLOCK 4u
#endif

#ifndef NUM_REGS
#define NUM_REGS 32u
#endif

// External MIPS-style logical bases used by the assembler and address translator.
#define CRYPTO3D_MIPS_TEXT_BASE_BYTE 0x00400000u
#define CRYPTO3D_MIPS_DATA_BASE_BYTE 0x10010000u

// Secure header starts at word 0.  The encrypted .text image starts after the
// fixed 32-word secure metadata block.
#define SEC_HDR_WORDS          32u
#define SEC_TEXT_START_WORD    SEC_HDR_WORDS

// -----------------------------------------------------------------------------
// Secure image header identity and flags
// -----------------------------------------------------------------------------
#define SEC_HDR_MAGIC          0x33444352u  // ASCII: "3DCR"
#define SEC_HDR_VERSION        0x00020000u

#define SEC_HDR_FLAG_SINGLE_LAYER  0x00000001u
#define SEC_HDR_FLAG_WRAPPED_KEY   0x00000002u
#define SEC_HDR_FLAG_HKDF          0x00000004u
#define SEC_HDR_FLAG_MAPPED_TEXT   0x00000008u

#define SEC_HDR_FLAGS (SEC_HDR_FLAG_SINGLE_LAYER | \
                       SEC_HDR_FLAG_WRAPPED_KEY  | \
                       SEC_HDR_FLAG_HKDF         | \
                       SEC_HDR_FLAG_MAPPED_TEXT)

// -----------------------------------------------------------------------------
// Secure execution policy bits
// -----------------------------------------------------------------------------
#define SEC_POLICY_MAP_ENABLED     0x00000001u
#define SEC_POLICY_STRICT_TAMPER   0x00000002u
#define SEC_POLICY_RESEAL_READY    0x00000004u

#define SEC_POLICY_DEFAULT (SEC_POLICY_MAP_ENABLED   | \
                            SEC_POLICY_STRICT_TAMPER | \
                            SEC_POLICY_RESEAL_READY)

// -----------------------------------------------------------------------------
// Secure data-region flags
// -----------------------------------------------------------------------------
#define SEC_DATA_FLAG_ENCRYPTED    0x00000001u

// -----------------------------------------------------------------------------
// Crypto3DStackCPU_top status word layout
// -----------------------------------------------------------------------------
#define SEC_STATUS_SECURITY_LOCK   0x00000001u
#define SEC_STATUS_KEYCHECK_FAIL   0x00000002u
#define SEC_STATUS_RETIRED_SHIFT   16u
#define SEC_STATUS_RETIRED_MASK    0xFFFF0000u


// -----------------------------------------------------------------------------
// Software-visible performance counter IDs for Crypto3DStackCPU_get_perf_counter
// -----------------------------------------------------------------------------
#define CRYPTO3D_PERF_CYCLES              0u
#define CRYPTO3D_PERF_RETIRED             1u
#define CRYPTO3D_PERF_STALLS              2u
#define CRYPTO3D_PERF_LOAD_USE_STALLS     3u
#define CRYPTO3D_PERF_BRANCH_PREDICTIONS  4u
#define CRYPTO3D_PERF_BRANCH_MISPREDICTS  5u
#define CRYPTO3D_PERF_ICACHE_HITS         6u
#define CRYPTO3D_PERF_ICACHE_MISSES       7u
#define CRYPTO3D_PERF_DCACHE_HITS         8u
#define CRYPTO3D_PERF_DCACHE_MISSES       9u
#define CRYPTO3D_PERF_FORWARD_MEM         10u
#define CRYPTO3D_PERF_FORWARD_WB          11u
#define CRYPTO3D_PERF_STORE_DATA_FORWARDS 12u
#define CRYPTO3D_PERF_AES_INSTRUCTIONS    13u

// -----------------------------------------------------------------------------
// Secure image header layout, word offsets in the selected sealed-image layer
// -----------------------------------------------------------------------------
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

#ifdef __cplusplus
static_assert(SEC_HDR_WORDS == 32u, "Secure header must remain 32 words");
static_assert(SEC_TEXT_START_WORD == 32u, "Text region must start after header");
static_assert((SEC_HDR_FLAGS & SEC_HDR_FLAG_SINGLE_LAYER) != 0u, "Layer-0 sealed-image compatibility flag required");
static_assert((SEC_HDR_FLAGS & SEC_HDR_FLAG_WRAPPED_KEY)  != 0u, "Wrapped-key flag required");
static_assert((SEC_HDR_FLAGS & SEC_HDR_FLAG_HKDF)         != 0u, "HKDF flag required");
static_assert((SEC_HDR_FLAGS & SEC_HDR_FLAG_MAPPED_TEXT)  != 0u, "Mapped-text flag required");
extern "C" {
#endif

// -----------------------------------------------------------------------------
// CPU layer selection / secure image functions implemented in 3d.cpp
// -----------------------------------------------------------------------------

// Select instruction and data memory layers. The default validated boot path
// uses layer 0 for both, while the 4-layer memory model allows future tests and
// integrations to select other valid layers. Invalid selection locks security.
void CPU_set_layers(uint32_t instruction_layer, uint32_t data_layer);

// -----------------------------------------------------------------------------
// Secure image creation / validation functions implemented in 3d.cpp
// -----------------------------------------------------------------------------

// Creates the secure 32-word header, wraps the application key, hides the
// wrapped-key copy in the non-text region, and computes key/image tags.
int create_large_block_with_key(uint32_t layer, uint32_t key[4]);

// Validates the secure image and extracts the application key into key[4].
// The caller must zeroize key[4] after use.
int extract_key_from_large_block(uint32_t layer, uint32_t key[4]);

// Configure secure text metadata before create_large_block_with_key().
// text_start_addr, text_plain_words, and text_enc_end are word addresses/counts.
void secure_set_image_region(uint32_t text_start_addr,
                             uint32_t text_plain_words,
                             uint32_t text_enc_end);

// Configure secure data metadata before create_large_block_with_key().
// data_start_addr and data_enc_end are word addresses. data_plain_words is a
// word count before AES-block padding. data_flags normally includes
// SEC_DATA_FLAG_ENCRYPTED.
void secure_set_data_region(uint32_t data_start_addr,
                            uint32_t data_plain_words,
                            uint32_t data_enc_end,
                            uint32_t data_flags);

// Configure the logical-to-physical text-block mapping epoch. Passing zero is
// normalized by the implementation to a non-zero epoch.
void secure_set_mapping_epoch(uint32_t epoch);

// Map a logical text block to its physical encrypted block address using the
// active configured/header policy.
uint32_t secure_map_text_block(uint32_t logical_block_addr);

// Read active secure text metadata. If a validated runtime header exists, the
// runtime header values are returned; otherwise the configured values are used.
int secure_get_image_region(uint32_t *text_start_addr,
                            uint32_t *text_plain_words,
                            uint32_t *text_enc_end,
                            uint32_t *epoch);

// Read active secure data metadata. If a validated runtime header exists, the
// runtime header values are returned; otherwise the configured values are used.
int secure_get_data_region(uint32_t *data_start_addr,
                           uint32_t *data_plain_words,
                           uint32_t *data_enc_end,
                           uint32_t *data_flags);

// Verify the secure image header, hidden wrapped-key copy, measurement tag,
// key tag, and image tag. On failure the implementation may lock security state.
int secure_validate_image(uint32_t layer);

// Decrypt and read a single data word in plaintext using the wrapped image key.
// Used by the testbench for contract/signature validation without exposing the
// application key to the caller.
int secure_read_data_word_plain(uint32_t word_addr, uint32_t *plain_value);


// Read an architectural performance counter after Crypto3DStackCPU_top() returns.
uint32_t Crypto3DStackCPU_get_perf_counter(uint32_t counter_id);

// -----------------------------------------------------------------------------
// AES block primitives implemented in 3d.cpp
// -----------------------------------------------------------------------------
void aes_encrypt_block(uint32_t in[4], uint32_t key[4], uint32_t out[4]);
void aes_decrypt_block(uint32_t in[4], uint32_t key[4], uint32_t out[4]);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // CRYPTO3D_HEADER_H
