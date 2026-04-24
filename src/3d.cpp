// ============================================================================
// 3D Stacked Memory Model Abstraction (Extended)
// ============================================================================


#include <cstdint>
#include <cstring>
#include <cstddef>

#if !defined(__SYNTHESIS__)
#include <cstdio>
#endif

#include "3d.h"
#include "header.h"

#ifndef TRACE_PIPELINE
#define TRACE_PIPELINE 0
#endif

#ifndef TRACE_POST_TEXT_DUMP
#define TRACE_POST_TEXT_DUMP 0
#endif

#ifndef CRYPTO3D_ENABLE_OUTPUT_RESEAL
#define CRYPTO3D_ENABLE_OUTPUT_RESEAL 1
#endif

#ifndef CRYPTO3D_STRICT_TEXT_WRITE_PROTECT
#define CRYPTO3D_STRICT_TEXT_WRITE_PROTECT 1
#endif


// ------------------------------------------------------------------------
// Global Parameters / Definitions
// ------------------------------------------------------------------------
#define AES_BLOCK_SIZE    16
#define NUM_REGS          32
#define MEM_SIZE          1024
#define INSTRS_PER_BLOCK  4
#define ICACHE_LINES      4
#define DCACHE_LINES      4

// ------------------------------------------------------------------------
// Targeted i-cache invalidation for self-modifying code
static constexpr uint32_t kTextStartBlock = 8;
static constexpr uint32_t kTextStartAddr  = kTextStartBlock * INSTRS_PER_BLOCK;
static constexpr uint32_t kMarsTextBaseWord = 0x00100000u; // 0x00400000 / 4
static constexpr uint32_t kMarsDataBaseByte = 0x10010000u;

static inline void invalidateICacheWordAddr(uint32_t word_addr); // forward declaration
static inline void invalidateFrontendOnTextWrite(uint32_t word_addr); // forward declaration
static uint32_t secure_map_text_block_runtime(uint32_t logical_block_addr); // forward declaration

// Forward declarations for AES functions
// ------------------------------------------------------------------------
extern "C" void aes_encrypt_block(uint32_t*, uint32_t*, uint32_t*);
extern "C" void aes_decrypt_block(uint32_t*, uint32_t*, uint32_t*);

// ------------------------------------------------------------------------
// HLS-compatible static sizes
// ------------------------------------------------------------------------
#define MAX_LAYERS   4
#define MAX_WORDS    1024
#define MAX_LOG_LEN 128


StackedMemory3D stackedMemory(MAX_LAYERS, MEM_SIZE); // 4-layer 3D stack, 1024 words/layer

// ------------------------------------------------------------------------
// Instruction Opcodes
// ------------------------------------------------------------------------
enum OPCODES {
    NOP     = 0,
    ADD     = 1,
    SUB     = 2,
    LW      = 3,
    SW      = 4,
    AES_ENC = 5,
    AES_DEC = 6,
    AND_    = 7,
    OR_     = 8,
    XOR_    = 9,
    SLL     = 10,
    SRL     = 11,
    MULT    = 12,
    BEQ     = 13,
    BNE     = 14,
    J       = 15
};

// ------------------------------------------------------------------------
// Instruction Union
// ------------------------------------------------------------------------
typedef union {
    uint32_t raw;
    struct {
        uint32_t opcode : 6;
        uint32_t rs     : 5;
        uint32_t rt     : 5;
        uint32_t rd     : 5;
        uint32_t shamt  : 5;
        uint32_t funct  : 6;
    } r_type;
    struct {
        uint32_t opcode : 6;
        uint32_t rs     : 5;
        uint32_t rt     : 5;
        uint32_t imm    : 16;
    } i_type;
    struct {
        uint32_t opcode : 6;
        uint32_t target : 26;
    } j_type;
} InstructionUnion;

// ============================================================================
// ================  GLOBAL STRUCTURES - REGISTERS - MEMORY  ====================
// ============================================================================

// Backed by the StackedMemory3D abstraction.
uint32_t reg_file[NUM_REGS];

// Global counter for retired instructions
static uint32_t retired_instructions = 0;

// Layer selectors
static uint32_t instr_layer = 0;
static uint32_t data_layer  = 0;

extern "C" void CPU_set_layers(uint32_t il, uint32_t dl) {
    if (il < stackedMemory.getNumLayers() && dl < stackedMemory.getNumLayers()) {
        instr_layer = il;
        data_layer  = dl;
    } else {
        instr_layer = 0;
        data_layer  = 0;
        stackedMemory.lockSecurity("BAD LAYER SELECT");
    }
    invalidateCaches();
}

static bool key_check_failed = false;
static bool key_valid = false;
static uint32_t runtime_app_key[4] = {0, 0, 0, 0};
static uint32_t copro_reg[4];

int secret_map[128] = {
    849, 171, 458, 347, 306, 11, 1023, 282, 
    948, 361, 329, 145, 456, 499, 334, 535,
    633, 416, 924, 50, 670, 73, 20, 906,
    680, 673, 108, 491, 900, 552, 419, 121,
    182, 421, 824, 479, 796, 628, 135, 124,
    604, 147, 157, 693, 515, 821, 90, 784,
    138, 269, 66, 732, 823, 1011, 53, 118,
    711, 684, 117, 753, 195, 496, 97, 898,
    651, 418, 695, 713, 122, 591, 556, 669,
    265, 346, 634, 630, 1003, 790, 144, 384,
    657, 636, 1002, 493, 55, 873, 475, 861,
    573, 537, 782, 601, 471, 595, 1000, 915,
    596, 3, 714, 632, 311, 649, 660, 150,
    706, 372, 724, 923, 485, 609, 363, 336,
    41, 85, 451, 249, 587, 956, 79, 480,
    743, 198, 500, 447, 996, 908, 351, 380
};

// ------------------------------------------------------------------------
// Architectural performance counters (software-visible after top returns)
// ------------------------------------------------------------------------
static uint32_t perf_cycle_count = 0;
static uint32_t perf_icache_hits = 0;
static uint32_t perf_icache_misses = 0;
static uint32_t perf_dcache_hits = 0;
static uint32_t perf_dcache_misses = 0;
static uint32_t perf_forward_mem = 0;
static uint32_t perf_forward_wb = 0;
static uint32_t perf_load_use_stalls = 0;
static uint32_t perf_store_data_forwards = 0;
static uint32_t perf_aes_instructions = 0;

// ------------------------------------------------------------------------
// I-cache (instruction cache)
// ------------------------------------------------------------------------

static uint32_t iCache_data[ICACHE_LINES][INSTRS_PER_BLOCK];
static uint32_t iCache_tag[ICACHE_LINES];
static bool     iCache_valid[ICACHE_LINES];

static inline void invalidateICacheWordAddr(uint32_t word_addr) {
    uint32_t block_addr = word_addr / INSTRS_PER_BLOCK;
    uint32_t index = block_addr % ICACHE_LINES;
    uint32_t tag   = block_addr / ICACHE_LINES;
    if (iCache_valid[index] && iCache_tag[index] == tag) {
        iCache_valid[index] = false;
    }
}

static void icache_get_index_tag(uint32_t block_addr, uint32_t &index, uint32_t &tag) {
#pragma HLS INLINE
    index = block_addr % ICACHE_LINES;
    tag   = block_addr / ICACHE_LINES;
}

static void icache_fetch_block_from_mem(uint32_t block_addr, uint32_t out_block[INSTRS_PER_BLOCK]) {
#pragma HLS INLINE off
    const uint32_t phys_words  = stackedMemory.getNumWords();
    const uint32_t max_blocks  = phys_words / INSTRS_PER_BLOCK;
    const uint32_t phys_block_addr = secure_map_text_block_runtime(block_addr);
    if (phys_block_addr >= max_blocks) {
        for (int i = 0; i < INSTRS_PER_BLOCK; i++) out_block[i] = 0;
        return;
    }
    uint32_t base = phys_block_addr * INSTRS_PER_BLOCK;
    for (int i = 0; i < INSTRS_PER_BLOCK; i++) {
        out_block[i] = stackedMemory.rawRead(instr_layer, base + i);
    }
}

static void icache_read_block(uint32_t block_addr, uint32_t out_block[INSTRS_PER_BLOCK]) {
#pragma HLS INLINE off
    uint32_t index, tag;
    icache_get_index_tag(block_addr, index, tag);
    if (!iCache_valid[index] || iCache_tag[index] != tag) {
        perf_icache_misses++;
        icache_fetch_block_from_mem(block_addr, iCache_data[index]);
        iCache_tag[index]   = tag;
        iCache_valid[index] = true;
    } else {
        perf_icache_hits++;
    }
    for (int i = 0; i < INSTRS_PER_BLOCK; i++) {
        out_block[i] = iCache_data[index][i];
    }
}

// ============================================================================
// ================  D-cache (data cache)  ====================================
// ============================================================================

static uint32_t dcache_data[DCACHE_LINES];
static uint32_t dcache_tag[DCACHE_LINES];
static bool     dcache_valid[DCACHE_LINES];
// ------------------------------------------------------------------------
// Cache Invalidation Helper (definition here, after globals)
// ------------------------------------------------------------------------
void invalidateCaches() {
    for (int i = 0; i < ICACHE_LINES; ++i) iCache_valid[i] = false;
    for (int i = 0; i < DCACHE_LINES; ++i) dcache_valid[i] = false;
}

static void dcache_get_index_tag(uint32_t addr, uint32_t &index, uint32_t &tag) {
#pragma HLS INLINE
    index = addr % DCACHE_LINES;
    tag   = addr / DCACHE_LINES;
}

static uint32_t dcache_read(uint32_t addr) {
#pragma HLS INLINE off
    uint32_t index, tag;
    dcache_get_index_tag(addr, index, tag);
    if (!dcache_valid[index] || dcache_tag[index] != tag) {
        perf_dcache_misses++;
        dcache_data[index]  = stackedMemory.protectedRead(data_layer, addr);
        dcache_tag[index]   = tag;
        dcache_valid[index] = true;
    } else {
        perf_dcache_hits++;
    }
    return dcache_data[index];
}

static void dcache_write(uint32_t addr, uint32_t value) {
#pragma HLS INLINE off
    uint32_t index, tag;
    dcache_get_index_tag(addr, index, tag);
    dcache_data[index]  = value;
    dcache_tag[index]   = tag;
    dcache_valid[index] = true;
    stackedMemory.protectedWrite(data_layer, addr, value);
}

// ============================================================================
// ================  Key Extraction / Derivation Helpers  =====================
// ============================================================================

static uint32_t secure_text_start_addr  = kTextStartAddr;
static uint32_t secure_text_plain_words = 0;
static uint32_t secure_text_enc_end     = kTextStartAddr;
static uint32_t secure_data_start_addr  = kTextStartAddr;
static uint32_t secure_data_plain_words = 0;
static uint32_t secure_data_enc_end     = kTextStartAddr;
static uint32_t secure_data_flags       = 0u;
static uint32_t secure_epoch            = 1;
static uint32_t secure_policy           = SEC_POLICY_MAP_ENABLED | SEC_POLICY_STRICT_TAMPER | SEC_POLICY_RESEAL_READY;

static bool secure_runtime_region_valid = false;
static uint32_t secure_runtime_text_start_addr  = kTextStartAddr;
static uint32_t secure_runtime_text_plain_words = 0;
static uint32_t secure_runtime_text_enc_end     = kTextStartAddr;
static uint32_t secure_runtime_data_start_addr  = kTextStartAddr;
static uint32_t secure_runtime_data_plain_words = 0;
static uint32_t secure_runtime_data_enc_end     = kTextStartAddr;
static uint32_t secure_runtime_data_flags       = 0u;
static uint32_t secure_runtime_epoch            = 1;

struct SecureMapParams {
    uint32_t start_block;
    uint32_t block_count;
    uint32_t mul;
    uint32_t add;
};

static SecureMapParams secure_runtime_map = {kTextStartBlock, 0u, 1u, 0u};
static bool secure_runtime_map_valid = false;

static inline void secure_zero_words(uint32_t *buf, int words) {
    volatile uint32_t *p = (volatile uint32_t *)buf;
    for (int i = 0; i < words; ++i) p[i] = 0;
}

static inline void secure_zero_bytes(uint8_t *buf, uint32_t len) {
    volatile uint8_t *p = (volatile uint8_t *)buf;
    for (uint32_t i = 0; i < len; ++i) p[i] = 0;
}

struct SecureHeaderState {
    uint32_t policy;
    uint32_t text_start;
    uint32_t text_words;
    uint32_t text_end;
    uint32_t data_start;
    uint32_t data_words;
    uint32_t data_end;
    uint32_t data_flags;
    uint32_t epoch;
    uint32_t nonce[4];
    uint32_t wrapped[4];
    uint32_t key_tag[4];
    uint32_t img_tag[4];
    uint32_t measurements[4];
};

static inline uint32_t rotl32(uint32_t x, int r) {
    return (x << r) | (x >> (32 - r));
}

static inline uint32_t secure_rotr32(uint32_t x, uint32_t r) {
    return (x >> r) | (x << (32 - r));
}

static inline uint32_t secure_prng_step(uint32_t x) {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x ? x : 0xA5A5A5A5u;
}

static inline uint32_t secure_gcd32(uint32_t a, uint32_t b) {
    while (b != 0u) {
        uint32_t t = a % b;
        a = b;
        b = t;
    }
    return a ? a : 1u;
}

static inline void secure_store_be32(uint8_t *dst, uint32_t x) {
    dst[0] = (uint8_t)((x >> 24) & 0xFFu);
    dst[1] = (uint8_t)((x >> 16) & 0xFFu);
    dst[2] = (uint8_t)((x >> 8) & 0xFFu);
    dst[3] = (uint8_t)(x & 0xFFu);
}

static inline uint32_t secure_load_be32(const uint8_t *src) {
    return ((uint32_t)src[0] << 24) |
           ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8) |
           ((uint32_t)src[3]);
}

static inline void secure_words_to_bytes(const uint32_t *words, int n_words, uint8_t *bytes_out) {
    for (int i = 0; i < n_words; ++i) {
        secure_store_be32(&bytes_out[i * 4], words[i]);
    }
}

static inline void secure_bytes_to_words(const uint8_t *bytes, int n_words, uint32_t *words_out) {
    for (int i = 0; i < n_words; ++i) {
        words_out[i] = secure_load_be32(&bytes[i * 4]);
    }
}

static void secure_build_map_params(uint32_t text_start, uint32_t text_end, uint32_t epoch, SecureMapParams &params) {
    params.start_block = text_start / INSTRS_PER_BLOCK;
    uint32_t end_block = text_end / INSTRS_PER_BLOCK;
    params.block_count = (end_block > params.start_block) ? (end_block - params.start_block) : 0u;
    params.mul = 1u;
    params.add = 0u;

    if (params.block_count <= 1u) {
        return;
    }

    uint32_t seed = epoch ^ (text_start * 0x9E3779B9u) ^ rotl32(text_end, 7) ^ 0xC001D00Du;
    seed = secure_prng_step(seed);

    uint32_t candidate = (seed % params.block_count) | 1u;
    if (candidate >= params.block_count) {
        candidate = (candidate % params.block_count) | 1u;
    }
    if (candidate == 0u) {
        candidate = 1u;
    }

    uint32_t guard = 0u;
    while (secure_gcd32(candidate, params.block_count) != 1u && guard < (params.block_count + 8u)) {
        candidate += 2u;
        if (candidate >= params.block_count) {
            candidate = (candidate % params.block_count) | 1u;
        }
        guard++;
    }
    if (secure_gcd32(candidate, params.block_count) != 1u) {
        candidate = 1u;
    }

    params.mul = candidate;
    params.add = secure_prng_step(seed ^ 0xA511E9B3u) % params.block_count;
}

static inline uint32_t secure_map_block_with_params(uint32_t logical_block_addr, const SecureMapParams &params) {
    if (params.block_count <= 1u) {
        return logical_block_addr;
    }
    uint32_t start = params.start_block;
    uint32_t stop  = params.start_block + params.block_count;
    if (logical_block_addr < start || logical_block_addr >= stop) {
        return logical_block_addr;
    }

    uint32_t idx = logical_block_addr - start;
    uint32_t mapped = (uint32_t)(((uint64_t)params.mul * (uint64_t)idx + (uint64_t)params.add) % params.block_count);
    return start + mapped;
}

extern "C" uint32_t secure_map_text_block(uint32_t logical_block_addr) {
    if (secure_runtime_map_valid) {
        return secure_map_block_with_params(logical_block_addr, secure_runtime_map);
    }

    SecureMapParams cfg;
    secure_build_map_params(secure_text_start_addr, secure_text_enc_end, secure_epoch, cfg);
    return secure_map_block_with_params(logical_block_addr, cfg);
}

static uint32_t secure_map_text_block_runtime(uint32_t logical_block_addr) {
    if (!secure_runtime_map_valid) {
        return logical_block_addr;
    }
    return secure_map_block_with_params(logical_block_addr, secure_runtime_map);
}

static void secure_apply_runtime_region(const SecureHeaderState &hdr) {
    secure_runtime_text_start_addr  = hdr.text_start;
    secure_runtime_text_plain_words = hdr.text_words;
    secure_runtime_text_enc_end     = hdr.text_end;
    secure_runtime_data_start_addr  = hdr.data_start;
    secure_runtime_data_plain_words = hdr.data_words;
    secure_runtime_data_enc_end     = hdr.data_end;
    secure_runtime_data_flags       = hdr.data_flags;
    secure_runtime_epoch            = hdr.epoch;
    secure_runtime_region_valid     = true;

    secure_build_map_params(hdr.text_start, hdr.text_end, hdr.epoch, secure_runtime_map);
    secure_runtime_map_valid = true;
}

// ------------------------------------------------------------------------
// SHA-256 / HMAC / HKDF helpers (fixed-width, no dynamic allocations)
// ------------------------------------------------------------------------

static const uint32_t kSha256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

struct Sha256Ctx {
    uint32_t state[8];
    uint8_t block[64];
    uint32_t block_len;
    uint64_t total_len;
};

static void sha256_transform(Sha256Ctx &ctx, const uint8_t data[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = secure_load_be32(&data[i * 4]);
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = secure_rotr32(w[i - 15], 7) ^ secure_rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = secure_rotr32(w[i - 2], 17) ^ secure_rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx.state[0];
    uint32_t b = ctx.state[1];
    uint32_t c = ctx.state[2];
    uint32_t d = ctx.state[3];
    uint32_t e = ctx.state[4];
    uint32_t f = ctx.state[5];
    uint32_t g = ctx.state[6];
    uint32_t h = ctx.state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = secure_rotr32(e, 6) ^ secure_rotr32(e, 11) ^ secure_rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + kSha256[i] + w[i];
        uint32_t S0 = secure_rotr32(a, 2) ^ secure_rotr32(a, 13) ^ secure_rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx.state[0] += a;
    ctx.state[1] += b;
    ctx.state[2] += c;
    ctx.state[3] += d;
    ctx.state[4] += e;
    ctx.state[5] += f;
    ctx.state[6] += g;
    ctx.state[7] += h;
}

static void sha256_init(Sha256Ctx &ctx) {
    ctx.state[0] = 0x6a09e667u;
    ctx.state[1] = 0xbb67ae85u;
    ctx.state[2] = 0x3c6ef372u;
    ctx.state[3] = 0xa54ff53au;
    ctx.state[4] = 0x510e527fu;
    ctx.state[5] = 0x9b05688cu;
    ctx.state[6] = 0x1f83d9abu;
    ctx.state[7] = 0x5be0cd19u;
    ctx.block_len = 0u;
    ctx.total_len = 0u;
}

static void sha256_update(Sha256Ctx &ctx, const uint8_t *data, uint32_t len) {
    for (uint32_t i = 0; i < len; ++i) {
        ctx.block[ctx.block_len++] = data[i];
        if (ctx.block_len == 64u) {
            sha256_transform(ctx, ctx.block);
            ctx.total_len += 64u;
            ctx.block_len = 0u;
        }
    }
}

static void sha256_update_word(Sha256Ctx &ctx, uint32_t word) {
    uint8_t b[4];
    secure_store_be32(b, word);
    sha256_update(ctx, b, 4u);
}

static void sha256_final(Sha256Ctx &ctx, uint8_t out[32]) {
    uint64_t total_bits = (ctx.total_len + ctx.block_len) * 8u;

    ctx.block[ctx.block_len++] = 0x80u;
    if (ctx.block_len > 56u) {
        while (ctx.block_len < 64u) ctx.block[ctx.block_len++] = 0u;
        sha256_transform(ctx, ctx.block);
        ctx.block_len = 0u;
    }
    while (ctx.block_len < 56u) ctx.block[ctx.block_len++] = 0u;

    for (int i = 7; i >= 0; --i) {
        ctx.block[ctx.block_len++] = (uint8_t)((total_bits >> (i * 8)) & 0xFFu);
    }
    sha256_transform(ctx, ctx.block);

    for (int i = 0; i < 8; ++i) {
        secure_store_be32(&out[i * 4], ctx.state[i]);
    }
}

static void hmac_sha256(const uint8_t *key,
                        uint32_t key_len,
                        const uint8_t *data,
                        uint32_t data_len,
                        uint8_t out[32]) {
    uint8_t key_block[64];
    for (int i = 0; i < 64; ++i) key_block[i] = 0u;

    if (key_len > 64u) {
        Sha256Ctx hctx;
        uint8_t kh[32];
        sha256_init(hctx);
        sha256_update(hctx, key, key_len);
        sha256_final(hctx, kh);
        for (int i = 0; i < 32; ++i) key_block[i] = kh[i];
        secure_zero_bytes(kh, 32u);
    } else {
        for (uint32_t i = 0; i < key_len; ++i) key_block[i] = key[i];
    }

    uint8_t ipad[64];
    uint8_t opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = (uint8_t)(key_block[i] ^ 0x36u);
        opad[i] = (uint8_t)(key_block[i] ^ 0x5Cu);
    }

    uint8_t inner_hash[32];
    Sha256Ctx ictx;
    sha256_init(ictx);
    sha256_update(ictx, ipad, 64u);
    sha256_update(ictx, data, data_len);
    sha256_final(ictx, inner_hash);

    Sha256Ctx octx;
    sha256_init(octx);
    sha256_update(octx, opad, 64u);
    sha256_update(octx, inner_hash, 32u);
    sha256_final(octx, out);

    secure_zero_bytes(key_block, 64u);
    secure_zero_bytes(ipad, 64u);
    secure_zero_bytes(opad, 64u);
    secure_zero_bytes(inner_hash, 32u);
}

static void hkdf_sha256(const uint8_t *ikm,
                        uint32_t ikm_len,
                        const uint8_t *salt,
                        uint32_t salt_len,
                        const uint8_t *info,
                        uint32_t info_len,
                        uint8_t *okm,
                        uint32_t okm_len) {
    uint8_t prk[32];
    uint8_t t[32];
    uint8_t msg[64];

    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);

    uint32_t generated = 0u;
    uint8_t counter = 1u;
    uint32_t t_len = 0u;

    while (generated < okm_len) {
        uint32_t m_len = 0u;
        for (uint32_t i = 0; i < t_len; ++i) msg[m_len++] = t[i];
        for (uint32_t i = 0; i < info_len; ++i) msg[m_len++] = info[i];
        msg[m_len++] = counter;

        hmac_sha256(prk, 32u, msg, m_len, t);
        t_len = 32u;

        uint32_t to_copy = (okm_len - generated > 32u) ? 32u : (okm_len - generated);
        for (uint32_t i = 0; i < to_copy; ++i) {
            okm[generated + i] = t[i];
        }
        generated += to_copy;
        counter++;
    }

    secure_zero_bytes(prk, 32u);
    secure_zero_bytes(t, 32u);
    secure_zero_bytes(msg, 64u);
}

static void secure_derive_nonce(const uint32_t app_key[4],
                                uint32_t text_start,
                                uint32_t text_words,
                                uint32_t text_end,
                                uint32_t data_start,
                                uint32_t data_words,
                                uint32_t data_end,
                                uint32_t data_flags,
                                uint32_t epoch,
                                uint32_t nonce[4]) {
    uint32_t seed = 0x6A09E667u ^ app_key[0] ^ rotl32(app_key[1], 5) ^ rotl32(app_key[2], 11) ^ rotl32(app_key[3], 17);
    seed ^= text_start * 0x9E3779B9u;
    seed ^= text_words * 0x85EBCA6Bu;
    seed ^= text_end * 0xC2B2AE35u;
    seed ^= data_start * 0x165667B1u;
    seed ^= data_words * 0xD3A2646Cu;
    seed ^= data_end * 0xB5297A4Du;
    seed ^= data_flags * 0x91E10DA5u;
    seed ^= epoch * 0x27D4EB2Du;

    for (int i = 0; i < 4; ++i) {
        seed = secure_prng_step(seed + 0x9E3779B9u + (uint32_t)i * 0x7F4A7C15u);
        nonce[i] = seed;
    }
}

static void secure_derive_root_from_nonce(const uint32_t nonce[4], uint32_t root[4]) {
    for (int i = 0; i < 4; ++i) {
        root[i] = stackedMemory.deriveHardwareWord(nonce[i], (uint32_t)(0x31u + i));
    }
}

static bool secure_generate_positions(const uint32_t nonce[4],
                                      uint32_t text_start,
                                      uint32_t text_end,
                                      uint32_t num_words,
                                      uint32_t positions[128]) {
    if (num_words <= SEC_HDR_WORDS) return false;

    uint32_t low = (num_words > 640u) ? 512u : (num_words / 2u);
    if (low < SEC_HDR_WORDS) low = SEC_HDR_WORDS;
    if (low >= num_words) return false;
    uint32_t high = num_words - 1u;
    uint32_t span = high - low + 1u;

    uint32_t seed = nonce[0] ^ rotl32(nonce[1], 3) ^ rotl32(nonce[2], 9) ^ rotl32(nonce[3], 15);
    seed ^= text_start * 0x9E3779B9u;
    seed ^= text_end * 0x85EBCA6Bu;

    for (int i = 0; i < 128; ++i) {
        bool placed = false;
        for (int attempt = 0; attempt < 2048; ++attempt) {
            seed = secure_prng_step(seed + 0xA511E9B3u + (uint32_t)i * 0x3C6EF372u + (uint32_t)attempt);
            uint32_t word = low + (seed % span);
            if (word < SEC_HDR_WORDS) continue;
            if (word >= text_start && word < text_end) continue;

            uint32_t bit = (seed >> 27) & 31u;
            uint32_t pos = word * 32u + bit;

            bool dup = false;
            for (int j = 0; j < i; ++j) {
                if (positions[j] == pos) {
                    dup = true;
                    break;
                }
            }
            if (dup) continue;

            positions[i] = pos;
            placed = true;
            break;
        }
        if (!placed) return false;
    }

    return true;
}

static void secure_extract_hidden_wrapped(uint32_t layer, const uint32_t positions[128], uint32_t wrapped_hidden[4]) {
    for (int i = 0; i < 4; ++i) wrapped_hidden[i] = 0;

    for (int i = 0; i < 128; ++i) {
        uint32_t bit_pos = positions[i];
        uint32_t word_index = bit_pos / 32u;
        uint32_t bit_in_word = bit_pos % 32u;

        uint32_t word_val = stackedMemory.protectedRead(layer, word_index);
        uint32_t bit_val = (word_val >> bit_in_word) & 1u;

        uint32_t key_word = (uint32_t)i / 32u;
        uint32_t key_bit  = (uint32_t)i % 32u;
        wrapped_hidden[key_word] |= (bit_val << key_bit);
    }
}

static void secure_hide_wrapped(uint32_t layer, const uint32_t positions[128], const uint32_t wrapped[4]) {
    for (int i = 0; i < 128; ++i) {
        uint32_t bit_pos = positions[i];
        uint32_t word_index = bit_pos / 32u;
        uint32_t bit_in_word = bit_pos % 32u;

        uint32_t key_word = (uint32_t)i / 32u;
        uint32_t key_bit  = (uint32_t)i % 32u;
        uint32_t bit_val  = (wrapped[key_word] >> key_bit) & 1u;

        uint32_t tmp = stackedMemory.protectedRead(layer, word_index);
        tmp &= ~(1u << bit_in_word);
        tmp |= (bit_val << bit_in_word);
        stackedMemory.protectedWrite(layer, word_index, tmp);

        secret_map[i] = (int)bit_pos;
    }
}

static bool secure_decode_header(uint32_t layer, SecureHeaderState& hdr) {
    const uint32_t words = (uint32_t)stackedMemory.getNumWords();
    if (words <= SEC_HDR_WORDS) return false;

    uint32_t magic   = stackedMemory.protectedRead(layer, SEC_HDR_W_MAGIC);
    uint32_t version = stackedMemory.protectedRead(layer, SEC_HDR_W_VERSION);
    uint32_t flags   = stackedMemory.protectedRead(layer, SEC_HDR_W_FLAGS);
    if (magic != SEC_HDR_MAGIC || version != SEC_HDR_VERSION || (flags & SEC_HDR_FLAGS) != SEC_HDR_FLAGS) {
        return false;
    }

    hdr.policy     = stackedMemory.protectedRead(layer, SEC_HDR_W_POLICY);
    hdr.text_start = stackedMemory.protectedRead(layer, SEC_HDR_W_TEXT_START);
    hdr.text_words = stackedMemory.protectedRead(layer, SEC_HDR_W_TEXT_WORDS);
    hdr.text_end   = stackedMemory.protectedRead(layer, SEC_HDR_W_TEXT_END);
    hdr.data_start = stackedMemory.protectedRead(layer, SEC_HDR_W_DATA_START);
    hdr.data_words = stackedMemory.protectedRead(layer, SEC_HDR_W_DATA_WORDS);
    hdr.data_end   = stackedMemory.protectedRead(layer, SEC_HDR_W_DATA_END);
    hdr.data_flags = stackedMemory.protectedRead(layer, SEC_HDR_W_DATA_FLAGS);
    hdr.epoch      = stackedMemory.protectedRead(layer, SEC_HDR_W_EPOCH);
    for (int i = 0; i < 4; ++i) hdr.nonce[i]        = stackedMemory.protectedRead(layer, SEC_HDR_W_NONCE0  + (uint32_t)i);
    for (int i = 0; i < 4; ++i) hdr.wrapped[i]      = stackedMemory.protectedRead(layer, SEC_HDR_W_WRAP0   + (uint32_t)i);
    for (int i = 0; i < 4; ++i) hdr.key_tag[i]      = stackedMemory.protectedRead(layer, SEC_HDR_W_KEYTAG0 + (uint32_t)i);
    for (int i = 0; i < 4; ++i) hdr.img_tag[i]      = stackedMemory.protectedRead(layer, SEC_HDR_W_IMGTAG0 + (uint32_t)i);
    for (int i = 0; i < 4; ++i) hdr.measurements[i] = stackedMemory.protectedRead(layer, SEC_HDR_W_MEAS0   + (uint32_t)i);

    if (hdr.text_start < kTextStartAddr) return false;
    if (hdr.text_start > words) return false;
    if (hdr.text_end < hdr.text_start || hdr.text_end > words) return false;
    if (hdr.text_words > (hdr.text_end - hdr.text_start)) return false;
    if (hdr.text_start % INSTRS_PER_BLOCK != 0) return false;
    if (hdr.text_end % INSTRS_PER_BLOCK != 0) return false;

    if (hdr.data_start < hdr.text_end) return false;
    if (hdr.data_start > words) return false;
    if (hdr.data_end < hdr.data_start || hdr.data_end > words) return false;
    if (hdr.data_words > (hdr.data_end - hdr.data_start)) return false;
    if (hdr.data_start % INSTRS_PER_BLOCK != 0) return false;
    if (hdr.data_end % INSTRS_PER_BLOCK != 0) return false;

    if (hdr.epoch == 0u) return false;

    return true;
}

static void secure_collect_measurements(uint32_t layer,
                                        const SecureHeaderState& hdr,
                                        uint32_t out_meas[4]) {
    Sha256Ctx ctx;
    uint8_t digest[32];
    const char domain[] = "MEAS-V2";

    sha256_init(ctx);
    sha256_update(ctx, (const uint8_t *)domain, (uint32_t)(sizeof(domain) - 1));
    sha256_update_word(ctx, SEC_HDR_MAGIC);
    sha256_update_word(ctx, SEC_HDR_VERSION);
    sha256_update_word(ctx, SEC_HDR_FLAGS);
    sha256_update_word(ctx, hdr.policy);
    sha256_update_word(ctx, hdr.text_start);
    sha256_update_word(ctx, hdr.text_words);
    sha256_update_word(ctx, hdr.text_end);
    sha256_update_word(ctx, hdr.data_start);
    sha256_update_word(ctx, hdr.data_words);
    sha256_update_word(ctx, hdr.data_end);
    sha256_update_word(ctx, hdr.data_flags);
    sha256_update_word(ctx, hdr.epoch);
    for (int i = 0; i < 4; ++i) {
        sha256_update_word(ctx, hdr.nonce[i]);
    }

    SecureMapParams map;
    secure_build_map_params(hdr.text_start, hdr.text_end, hdr.epoch, map);
    for (uint32_t addr = hdr.text_start; addr < hdr.text_end; ++addr) {
        uint32_t logical_block = addr / INSTRS_PER_BLOCK;
        uint32_t phys_block = secure_map_block_with_params(logical_block, map);
        uint32_t phys_addr = phys_block * INSTRS_PER_BLOCK + (addr % INSTRS_PER_BLOCK);
        sha256_update_word(ctx, stackedMemory.rawRead(layer, phys_addr));
    }

    sha256_final(ctx, digest);
    secure_bytes_to_words(digest, 4, out_meas);
    secure_zero_bytes(digest, 32u);
}

static void secure_derive_session_key(uint32_t layer,
                                      const SecureHeaderState& hdr,
                                      uint32_t session_key[4],
                                      uint32_t measurements[4]) {
    uint32_t root[4];
    uint8_t root_bytes[16];
    uint8_t salt[32];
    uint8_t info[48];
    uint8_t okm[16];

    secure_collect_measurements(layer, hdr, measurements);
    secure_derive_root_from_nonce(hdr.nonce, root);

    secure_words_to_bytes(root, 4, root_bytes);
    secure_words_to_bytes(hdr.nonce, 4, salt);
    secure_words_to_bytes(measurements, 4, &salt[16]);

    for (int i = 0; i < 48; ++i) info[i] = 0u;
    info[0] = '3'; info[1] = 'D'; info[2] = 'C'; info[3] = 'P';
    info[4] = 'U'; info[5] = '-'; info[6] = 'K'; info[7] = 'D';
    info[8] = 'F'; info[9] = '-'; info[10] = 'V'; info[11] = '2';
    secure_store_be32(&info[12], hdr.text_start);
    secure_store_be32(&info[16], hdr.text_words);
    secure_store_be32(&info[20], hdr.text_end);
    secure_store_be32(&info[24], hdr.data_start);
    secure_store_be32(&info[28], hdr.data_words);
    secure_store_be32(&info[32], hdr.data_end);
    secure_store_be32(&info[36], hdr.data_flags);
    secure_store_be32(&info[40], hdr.epoch);
    secure_store_be32(&info[44], hdr.policy);

    hkdf_sha256(root_bytes, 16u, salt, 32u, info, 48u, okm, 16u);
    secure_bytes_to_words(okm, 4, session_key);

    secure_zero_words(root, 4);
    secure_zero_bytes(root_bytes, 16u);
    secure_zero_bytes(salt, 32u);
    secure_zero_bytes(info, 48u);
    secure_zero_bytes(okm, 16u);
}

static void secure_compute_key_tag(const SecureHeaderState& hdr,
                                   const uint32_t wrapped_hidden[4],
                                   const uint32_t session_key[4],
                                   const uint32_t measurements[4],
                                   uint32_t out_tag[4]) {
    uint32_t msg_words[26];
    uint8_t msg_bytes[26 * 4];
    uint8_t key_bytes[16];
    uint8_t digest[32];
    int idx = 0;

    msg_words[idx++] = 0x4B455954u; // "KEYT"
    msg_words[idx++] = SEC_HDR_MAGIC;
    msg_words[idx++] = SEC_HDR_VERSION;
    msg_words[idx++] = SEC_HDR_FLAGS;
    msg_words[idx++] = hdr.policy;
    msg_words[idx++] = hdr.text_start;
    msg_words[idx++] = hdr.text_words;
    msg_words[idx++] = hdr.text_end;
    msg_words[idx++] = hdr.data_start;
    msg_words[idx++] = hdr.data_words;
    msg_words[idx++] = hdr.data_end;
    msg_words[idx++] = hdr.data_flags;
    msg_words[idx++] = hdr.epoch;
    for (int i = 0; i < 4; ++i) msg_words[idx++] = hdr.nonce[i];
    for (int i = 0; i < 4; ++i) msg_words[idx++] = wrapped_hidden[i];
    for (int i = 0; i < 4; ++i) msg_words[idx++] = measurements[i];

    secure_words_to_bytes(msg_words, idx, msg_bytes);
    secure_words_to_bytes(session_key, 4, key_bytes);
    hmac_sha256(key_bytes, 16u, msg_bytes, (uint32_t)(idx * 4), digest);
    secure_bytes_to_words(digest, 4, out_tag);

    secure_zero_words(msg_words, idx);
    secure_zero_bytes(msg_bytes, (uint32_t)(idx * 4));
    secure_zero_bytes(key_bytes, 16u);
    secure_zero_bytes(digest, 32u);
}

static void secure_compute_img_tag(uint32_t layer,
                                   const SecureHeaderState& hdr,
                                   const uint32_t session_key[4],
                                   const uint32_t measurements[4],
                                   uint32_t out_tag[4]) {
    uint32_t msg_words[MAX_WORDS + 64];
    uint8_t msg_bytes[(MAX_WORDS + 64) * 4];
    uint8_t key_bytes[16];
    uint8_t digest[32];
    int idx = 0;

    msg_words[idx++] = 0x494D4754u; // "IMGT"
    msg_words[idx++] = SEC_HDR_MAGIC;
    msg_words[idx++] = SEC_HDR_VERSION;
    msg_words[idx++] = SEC_HDR_FLAGS;
    msg_words[idx++] = hdr.policy;
    msg_words[idx++] = hdr.text_start;
    msg_words[idx++] = hdr.text_words;
    msg_words[idx++] = hdr.text_end;
    msg_words[idx++] = hdr.data_start;
    msg_words[idx++] = hdr.data_words;
    msg_words[idx++] = hdr.data_end;
    msg_words[idx++] = hdr.data_flags;
    msg_words[idx++] = hdr.epoch;
    for (int i = 0; i < 4; ++i) msg_words[idx++] = hdr.nonce[i];
    for (int i = 0; i < 4; ++i) msg_words[idx++] = measurements[i];

    SecureMapParams map;
    secure_build_map_params(hdr.text_start, hdr.text_end, hdr.epoch, map);
    for (uint32_t addr = hdr.text_start; addr < hdr.text_end; ++addr) {
        uint32_t logical_block = addr / INSTRS_PER_BLOCK;
        uint32_t phys_block = secure_map_block_with_params(logical_block, map);
        uint32_t phys_addr = phys_block * INSTRS_PER_BLOCK + (addr % INSTRS_PER_BLOCK);
        msg_words[idx++] = stackedMemory.rawRead(layer, phys_addr);
    }

    for (uint32_t addr = hdr.data_start; addr < hdr.data_end; ++addr) {
        msg_words[idx++] = stackedMemory.rawRead(layer, addr);
    }

    secure_words_to_bytes(msg_words, idx, msg_bytes);
    secure_words_to_bytes(session_key, 4, key_bytes);
    hmac_sha256(key_bytes, 16u, msg_bytes, (uint32_t)(idx * 4), digest);
    secure_bytes_to_words(digest, 4, out_tag);

    secure_zero_words(msg_words, idx);
    secure_zero_bytes(msg_bytes, (uint32_t)(idx * 4));
    secure_zero_bytes(key_bytes, 16u);
    secure_zero_bytes(digest, 32u);
}

static bool secure_equal_words(const uint32_t *a, const uint32_t *b, int n);

static int secure_reseal_current_image(uint32_t layer) {
    const uint32_t active_layer = 0u;
    (void)layer;

    SecureHeaderState hdr;
    if (!secure_decode_header(active_layer, hdr)) {
        stackedMemory.lockSecurity("RESEAL HEADER");
        return -1;
    }

    if ((hdr.policy & SEC_POLICY_RESEAL_READY) == 0u) {
        return 0;
    }

    uint32_t positions[128];
    if (!secure_generate_positions(hdr.nonce,
                                   hdr.text_start,
                                   hdr.text_end,
                                   (uint32_t)stackedMemory.getNumWords(),
                                   positions)) {
        stackedMemory.lockSecurity("RESEAL MAP");
        return -2;
    }

    uint32_t wrapped_hidden[4] = {0u, 0u, 0u, 0u};
    secure_extract_hidden_wrapped(active_layer, positions, wrapped_hidden);
    if (!secure_equal_words(wrapped_hidden, hdr.wrapped, 4)) {
        secure_zero_words(wrapped_hidden, 4);
        stackedMemory.lockSecurity("RESEAL WRAP");
        return -3;
    }

    uint32_t session_key[4]      = {0u, 0u, 0u, 0u};
    uint32_t measured_now[4]     = {0u, 0u, 0u, 0u};
    uint32_t expected_key_tag[4] = {0u, 0u, 0u, 0u};
    uint32_t new_img_tag[4]     = {0u, 0u, 0u, 0u};

    secure_derive_session_key(active_layer, hdr, session_key, measured_now);

    if (!secure_equal_words(measured_now, hdr.measurements, 4)) {
        secure_zero_words(session_key, 4);
        secure_zero_words(measured_now, 4);
        secure_zero_words(wrapped_hidden, 4);
        stackedMemory.lockSecurity("RESEAL MEAS");
        return -4;
    }

    secure_compute_key_tag(hdr, wrapped_hidden, session_key, measured_now, expected_key_tag);
    if (!secure_equal_words(expected_key_tag, hdr.key_tag, 4)) {
        secure_zero_words(session_key, 4);
        secure_zero_words(measured_now, 4);
        secure_zero_words(expected_key_tag, 4);
        secure_zero_words(wrapped_hidden, 4);
        stackedMemory.lockSecurity("RESEAL KEYTAG");
        return -5;
    }

    // Recompute the image authentication tag over the current encrypted text
    // and the current encrypted data region. This makes the post-execution
    // output image reloadable and authenticatable after runtime stores.
    secure_compute_img_tag(active_layer, hdr, session_key, measured_now, new_img_tag);

    for (int i = 0; i < 4; ++i) {
        hdr.img_tag[i] = new_img_tag[i];
        stackedMemory.protectedWrite(active_layer, SEC_HDR_W_IMGTAG0 + (uint32_t)i, new_img_tag[i]);
    }

    secure_apply_runtime_region(hdr);

    secure_zero_words(session_key, 4);
    secure_zero_words(measured_now, 4);
    secure_zero_words(expected_key_tag, 4);
    secure_zero_words(new_img_tag, 4);
    secure_zero_words(wrapped_hidden, 4);
    return 0;
}

static bool secure_equal_words(const uint32_t *a, const uint32_t *b, int n) {
    uint32_t diff = 0u;
    for (int i = 0; i < n; ++i) {
        diff |= (a[i] ^ b[i]);
    }
    return diff == 0u;
}

extern "C" void secure_set_image_region(uint32_t text_start_addr, uint32_t text_plain_words, uint32_t text_enc_end) {
    uint32_t words = (uint32_t)stackedMemory.getNumWords();

    secure_text_start_addr = text_start_addr;
    secure_text_plain_words = text_plain_words;
    secure_text_enc_end = text_enc_end;

    if (secure_text_start_addr < kTextStartAddr) secure_text_start_addr = kTextStartAddr;
    if (secure_text_start_addr > words) secure_text_start_addr = kTextStartAddr;
    if (secure_text_enc_end < secure_text_start_addr) secure_text_enc_end = secure_text_start_addr;
    if (secure_text_enc_end > words) secure_text_enc_end = words;
    if (secure_text_plain_words > (secure_text_enc_end - secure_text_start_addr)) {
        secure_text_plain_words = secure_text_enc_end - secure_text_start_addr;
    }

    if (secure_data_start_addr < secure_text_enc_end) {
        secure_data_start_addr = secure_text_enc_end;
    }
    if (secure_data_start_addr > words) {
        secure_data_start_addr = secure_text_enc_end;
    }
    if (secure_data_enc_end < secure_data_start_addr) {
        secure_data_enc_end = secure_data_start_addr;
    }
    if (secure_data_enc_end > words) {
        secure_data_enc_end = words;
    }
    if (secure_data_plain_words > (secure_data_enc_end - secure_data_start_addr)) {
        secure_data_plain_words = secure_data_enc_end - secure_data_start_addr;
    }

    secure_runtime_region_valid = false;
    secure_runtime_map_valid = false;
}

extern "C" void secure_set_data_region(uint32_t data_start_addr,
                                        uint32_t data_plain_words,
                                        uint32_t data_enc_end,
                                        uint32_t data_flags) {
    uint32_t words = (uint32_t)stackedMemory.getNumWords();

    secure_data_start_addr = data_start_addr;
    secure_data_plain_words = data_plain_words;
    secure_data_enc_end = data_enc_end;
    secure_data_flags = data_flags;

    if (secure_data_start_addr < secure_text_enc_end) secure_data_start_addr = secure_text_enc_end;
    if (secure_data_start_addr > words) secure_data_start_addr = secure_text_enc_end;
    if (secure_data_enc_end < secure_data_start_addr) secure_data_enc_end = secure_data_start_addr;
    if (secure_data_enc_end > words) secure_data_enc_end = words;
    if (secure_data_plain_words > (secure_data_enc_end - secure_data_start_addr)) {
        secure_data_plain_words = secure_data_enc_end - secure_data_start_addr;
    }
    if (secure_data_start_addr % INSTRS_PER_BLOCK != 0u) {
        secure_data_start_addr -= (secure_data_start_addr % INSTRS_PER_BLOCK);
        if (secure_data_start_addr < secure_text_enc_end) {
            secure_data_start_addr = secure_text_enc_end;
        }
    }
    if (secure_data_enc_end % INSTRS_PER_BLOCK != 0u) {
        secure_data_enc_end += (INSTRS_PER_BLOCK - (secure_data_enc_end % INSTRS_PER_BLOCK));
        if (secure_data_enc_end > words) secure_data_enc_end = words;
    }

    secure_runtime_region_valid = false;
}

extern "C" void secure_set_mapping_epoch(uint32_t epoch) {
    secure_epoch = (epoch == 0u) ? 1u : epoch;
    secure_runtime_region_valid = false;
    secure_runtime_map_valid = false;
}

extern "C" int secure_get_image_region(uint32_t *text_start_addr,
                                        uint32_t *text_plain_words,
                                        uint32_t *text_enc_end,
                                        uint32_t *epoch) {
    if (text_start_addr == nullptr || text_plain_words == nullptr || text_enc_end == nullptr || epoch == nullptr) {
        return -1;
    }

    if (secure_runtime_region_valid) {
        *text_start_addr = secure_runtime_text_start_addr;
        *text_plain_words = secure_runtime_text_plain_words;
        *text_enc_end = secure_runtime_text_enc_end;
        *epoch = secure_runtime_epoch;
        return 0;
    }

    *text_start_addr = secure_text_start_addr;
    *text_plain_words = secure_text_plain_words;
    *text_enc_end = secure_text_enc_end;
    *epoch = secure_epoch;
    return 0;
}

extern "C" int secure_get_data_region(uint32_t *data_start_addr,
                                       uint32_t *data_plain_words,
                                       uint32_t *data_enc_end,
                                       uint32_t *data_flags) {
    if (data_start_addr == nullptr || data_plain_words == nullptr || data_enc_end == nullptr || data_flags == nullptr) {
        return -1;
    }

    if (secure_runtime_region_valid) {
        *data_start_addr = secure_runtime_data_start_addr;
        *data_plain_words = secure_runtime_data_plain_words;
        *data_enc_end = secure_runtime_data_enc_end;
        *data_flags = secure_runtime_data_flags;
        return 0;
    }

    *data_start_addr = secure_data_start_addr;
    *data_plain_words = secure_data_plain_words;
    *data_enc_end = secure_data_enc_end;
    *data_flags = secure_data_flags;
    return 0;
}

extern "C" int secure_validate_image(uint32_t layer) {
    if (layer >= stackedMemory.getNumLayers()) {
        stackedMemory.lockSecurity("BAD VALIDATE LAYER");
        return -100;
    }
    const uint32_t active_layer = layer;

    SecureHeaderState hdr;
    if (!secure_decode_header(active_layer, hdr)) {
        stackedMemory.lockSecurity("BAD HEADER");
        return -1;
    }

    uint32_t positions[128];
    if (!secure_generate_positions(hdr.nonce, hdr.text_start, hdr.text_end,
                                   (uint32_t)stackedMemory.getNumWords(), positions)) {
        stackedMemory.lockSecurity("BAD MAP");
        return -2;
    }

    uint32_t wrapped_hidden[4];
    secure_extract_hidden_wrapped(active_layer, positions, wrapped_hidden);
    if (!secure_equal_words(wrapped_hidden, hdr.wrapped, 4)) {
        stackedMemory.lockSecurity("WRAP MISMATCH");
        return -3;
    }

    uint32_t session_key[4];
    uint32_t measured_now[4];
    uint32_t expected_key_tag[4];
    uint32_t expected_img_tag[4];

    secure_derive_session_key(active_layer, hdr, session_key, measured_now);
    if (!secure_equal_words(measured_now, hdr.measurements, 4)) {
        secure_zero_words(session_key, 4);
        stackedMemory.lockSecurity("MEAS");
        return -4;
    }

    secure_compute_key_tag(hdr, wrapped_hidden, session_key, measured_now, expected_key_tag);
    if (!secure_equal_words(expected_key_tag, hdr.key_tag, 4)) {
        secure_zero_words(session_key, 4);
        stackedMemory.lockSecurity("KEY TAG");
        return -5;
    }

    secure_compute_img_tag(active_layer, hdr, session_key, measured_now, expected_img_tag);
    secure_zero_words(session_key, 4);
    if (!secure_equal_words(expected_img_tag, hdr.img_tag, 4)) {
        stackedMemory.lockSecurity("IMG TAG");
        return -6;
    }

    secure_apply_runtime_region(hdr);
    return 0;
}

extern "C" int secure_read_data_word_plain(uint32_t word_addr, uint32_t *plain_value) {
    if (plain_value == nullptr) return -1;

    const uint32_t active_layer = 0;
    const uint32_t words = (uint32_t)stackedMemory.getNumWords();
    if (word_addr >= words) return -2;

    SecureHeaderState hdr;
    if (!secure_decode_header(active_layer, hdr)) {
        return -3;
    }

    uint32_t positions[128];
    if (!secure_generate_positions(hdr.nonce, hdr.text_start, hdr.text_end, words, positions)) {
        return -4;
    }

    uint32_t wrapped_hidden[4];
    secure_extract_hidden_wrapped(active_layer, positions, wrapped_hidden);
    if (!secure_equal_words(wrapped_hidden, hdr.wrapped, 4)) {
        return -5;
    }

    uint32_t session_key[4];
    uint32_t measured_now[4];
    secure_derive_session_key(active_layer, hdr, session_key, measured_now);
    if (!secure_equal_words(measured_now, hdr.measurements, 4)) {
        secure_zero_words(session_key, 4);
        secure_zero_words(measured_now, 4);
        return -6;
    }

    uint32_t expected_key_tag[4];
    secure_compute_key_tag(hdr, wrapped_hidden, session_key, measured_now, expected_key_tag);
    if (!secure_equal_words(expected_key_tag, hdr.key_tag, 4)) {
        secure_zero_words(session_key, 4);
        secure_zero_words(measured_now, 4);
        secure_zero_words(expected_key_tag, 4);
        return -7;
    }

    uint32_t app_key[4] = {0u, 0u, 0u, 0u};
    aes_decrypt_block((uint32_t *)hdr.wrapped, session_key, app_key);

    secure_zero_words(session_key, 4);
    secure_zero_words(measured_now, 4);
    secure_zero_words(expected_key_tag, 4);

    if ((hdr.data_flags & SEC_DATA_FLAG_ENCRYPTED) == 0u || word_addr < hdr.data_start || word_addr >= hdr.data_end) {
        *plain_value = stackedMemory.protectedRead(active_layer, word_addr);
        secure_zero_words(app_key, 4);
        return 0;
    }

    uint32_t base = (word_addr / INSTRS_PER_BLOCK) * INSTRS_PER_BLOCK;
    if ((base + INSTRS_PER_BLOCK) > words) {
        secure_zero_words(app_key, 4);
        return -8;
    }

    uint32_t cipher[INSTRS_PER_BLOCK];
    uint32_t plain[INSTRS_PER_BLOCK];
    for (int i = 0; i < INSTRS_PER_BLOCK; ++i) {
        cipher[i] = stackedMemory.rawRead(active_layer, base + (uint32_t)i);
    }
    aes_decrypt_block(cipher, app_key, plain);
    *plain_value = plain[word_addr % INSTRS_PER_BLOCK];

    secure_zero_words(app_key, 4);
    secure_zero_words(plain, INSTRS_PER_BLOCK);
    secure_zero_words(cipher, INSTRS_PER_BLOCK);
    return 0;
}

extern "C" int extract_key_from_large_block(uint32_t layer, uint32_t key[4]) {
    if (layer >= stackedMemory.getNumLayers()) {
        for (int i = 0; i < 4; ++i) key[i] = 0;
        stackedMemory.lockSecurity("BAD EXTRACT LAYER");
        return -100;
    }
    const uint32_t active_layer = layer;

    for (int i = 0; i < 4; ++i) key[i] = 0;

    int rc = secure_validate_image(active_layer);
    if (rc != 0) {
        return rc;
    }

    SecureHeaderState hdr;
    if (!secure_decode_header(active_layer, hdr)) {
        stackedMemory.lockSecurity("BAD HEADER");
        return -10;
    }

    uint32_t session_key[4];
    uint32_t measured_now[4];
    secure_derive_session_key(active_layer, hdr, session_key, measured_now);
    aes_decrypt_block((uint32_t *)hdr.wrapped, session_key, key);

    secure_zero_words(session_key, 4);
    secure_zero_words(measured_now, 4);
    return 0;
}

extern "C" int create_large_block_with_key(uint32_t layer, uint32_t key[4]) {
    if (layer >= stackedMemory.getNumLayers()) {
        stackedMemory.lockSecurity("BAD CREATE LAYER");
        return -100;
    }
    const uint32_t active_layer = layer;
    const uint32_t words = (uint32_t)stackedMemory.getNumWords();

    SecureHeaderState hdr;
    hdr.policy     = secure_policy;
    hdr.text_start = secure_text_start_addr;
    hdr.text_words = secure_text_plain_words;
    hdr.text_end   = secure_text_enc_end;
    hdr.data_start = secure_data_start_addr;
    hdr.data_words = secure_data_plain_words;
    hdr.data_end   = secure_data_enc_end;
    hdr.data_flags = secure_data_flags;
    hdr.epoch      = (secure_epoch == 0u) ? 1u : secure_epoch;

    if (hdr.text_start < kTextStartAddr) hdr.text_start = kTextStartAddr;
    if (hdr.text_start > words) hdr.text_start = kTextStartAddr;
    if (hdr.text_end < hdr.text_start) hdr.text_end = hdr.text_start;
    if (hdr.text_end > words) hdr.text_end = words;
    if (hdr.text_words > (hdr.text_end - hdr.text_start)) {
        hdr.text_words = hdr.text_end - hdr.text_start;
    }

    if (hdr.data_start < hdr.text_end) hdr.data_start = hdr.text_end;
    if (hdr.data_start > words) hdr.data_start = hdr.text_end;
    if (hdr.data_end < hdr.data_start) hdr.data_end = hdr.data_start;
    if (hdr.data_end > words) hdr.data_end = words;
    if (hdr.data_words > (hdr.data_end - hdr.data_start)) {
        hdr.data_words = hdr.data_end - hdr.data_start;
    }
    if (hdr.data_start % INSTRS_PER_BLOCK != 0u) {
        hdr.data_start -= (hdr.data_start % INSTRS_PER_BLOCK);
        if (hdr.data_start < hdr.text_end) hdr.data_start = hdr.text_end;
    }
    if (hdr.data_end % INSTRS_PER_BLOCK != 0u) {
        hdr.data_end += (INSTRS_PER_BLOCK - (hdr.data_end % INSTRS_PER_BLOCK));
        if (hdr.data_end > words) hdr.data_end = words;
    }

    secure_derive_nonce(key,
                        hdr.text_start,
                        hdr.text_words,
                        hdr.text_end,
                        hdr.data_start,
                        hdr.data_words,
                        hdr.data_end,
                        hdr.data_flags,
                        hdr.epoch,
                        hdr.nonce);

    uint32_t session_key[4];
    uint32_t positions[128];
    uint32_t wrapped_hidden[4];
    uint32_t seed = hdr.nonce[0] ^ rotl32(hdr.nonce[1], 7) ^ 0xD00DFEEDu;

    for (uint32_t i = 0; i < SEC_HDR_WORDS; ++i) {
        seed = secure_prng_step(seed + i * 0x9E3779B9u);
        stackedMemory.protectedWrite(active_layer, i, seed);
    }

    secure_derive_session_key(active_layer, hdr, session_key, hdr.measurements);
    aes_encrypt_block(key, session_key, hdr.wrapped);

    stackedMemory.protectedWrite(active_layer, SEC_HDR_W_MAGIC, SEC_HDR_MAGIC);
    stackedMemory.protectedWrite(active_layer, SEC_HDR_W_VERSION, SEC_HDR_VERSION);
    stackedMemory.protectedWrite(active_layer, SEC_HDR_W_FLAGS, SEC_HDR_FLAGS);
    stackedMemory.protectedWrite(active_layer, SEC_HDR_W_POLICY, hdr.policy);
    stackedMemory.protectedWrite(active_layer, SEC_HDR_W_TEXT_START, hdr.text_start);
    stackedMemory.protectedWrite(active_layer, SEC_HDR_W_TEXT_WORDS, hdr.text_words);
    stackedMemory.protectedWrite(active_layer, SEC_HDR_W_TEXT_END, hdr.text_end);
    stackedMemory.protectedWrite(active_layer, SEC_HDR_W_DATA_START, hdr.data_start);
    stackedMemory.protectedWrite(active_layer, SEC_HDR_W_DATA_WORDS, hdr.data_words);
    stackedMemory.protectedWrite(active_layer, SEC_HDR_W_DATA_END, hdr.data_end);
    stackedMemory.protectedWrite(active_layer, SEC_HDR_W_DATA_FLAGS, hdr.data_flags);
    stackedMemory.protectedWrite(active_layer, SEC_HDR_W_EPOCH, hdr.epoch);
    for (int i = 0; i < 4; ++i) stackedMemory.protectedWrite(active_layer, SEC_HDR_W_NONCE0 + (uint32_t)i, hdr.nonce[i]);
    for (int i = 0; i < 4; ++i) stackedMemory.protectedWrite(active_layer, SEC_HDR_W_WRAP0 + (uint32_t)i, hdr.wrapped[i]);
    for (int i = 0; i < 4; ++i) stackedMemory.protectedWrite(active_layer, SEC_HDR_W_MEAS0 + (uint32_t)i, hdr.measurements[i]);

    if (!secure_generate_positions(hdr.nonce, hdr.text_start, hdr.text_end, words, positions)) {
        secure_zero_words(session_key, 4);
        stackedMemory.lockSecurity("NO HIDE MAP");
        return -20;
    }

    secure_hide_wrapped(active_layer, positions, hdr.wrapped);
    secure_extract_hidden_wrapped(active_layer, positions, wrapped_hidden);

    secure_compute_key_tag(hdr, wrapped_hidden, session_key, hdr.measurements, hdr.key_tag);
    secure_compute_img_tag(active_layer, hdr, session_key, hdr.measurements, hdr.img_tag);
    secure_zero_words(session_key, 4);

    for (int i = 0; i < 4; ++i) stackedMemory.protectedWrite(active_layer, SEC_HDR_W_KEYTAG0 + (uint32_t)i, hdr.key_tag[i]);
    for (int i = 0; i < 4; ++i) stackedMemory.protectedWrite(active_layer, SEC_HDR_W_IMGTAG0 + (uint32_t)i, hdr.img_tag[i]);

    secure_apply_runtime_region(hdr);
    return 0;
}

// ------------------------------------------------------------------------
// AES Code (Encrypt / Decrypt)
// ------------------------------------------------------------------------

static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t Rcon[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static uint8_t galois_mul(uint8_t a, uint8_t b) {
#pragma HLS INLINE
    uint8_t p = 0, hi;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static void add_round_key(uint8_t state[4][4], uint8_t rk[4][4]) {
#pragma HLS INLINE
    for (int i = 0; i < 4; i++) {
#pragma HLS UNROLL
        for (int j = 0; j < 4; j++) {
#pragma HLS UNROLL
            state[i][j] ^= rk[i][j];
        }
    }
}

static void sub_bytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
#pragma HLS UNROLL
        for (int j = 0; j < 4; j++) {
#pragma HLS UNROLL
            state[i][j] = sbox[state[i][j]];
        }
    }
}

static void inv_sub_bytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
#pragma HLS UNROLL
        for (int j = 0; j < 4; j++) {
#pragma HLS UNROLL
            state[i][j] = inv_sbox[state[i][j]];
        }
    }
}

static void shift_rows(uint8_t state[4][4]) {
    uint8_t tmp;
    tmp = state[1][0]; state[1][0]=state[1][1]; state[1][1]=state[1][2]; state[1][2]=state[1][3]; state[1][3]=tmp;
    tmp = state[2][0]; state[2][0]=state[2][2]; state[2][2]=tmp;
    tmp = state[2][1]; state[2][1]=state[2][3]; state[2][3]=tmp;
    tmp = state[3][3]; state[3][3]=state[3][2]; state[3][2]=state[3][1]; state[3][1]=state[3][0]; state[3][0]=tmp;
}

static void inv_shift_rows(uint8_t state[4][4]) {
    uint8_t tmp;
    tmp = state[1][3]; state[1][3]=state[1][2]; state[1][2]=state[1][1]; state[1][1]=state[1][0]; state[1][0]=tmp;
    tmp = state[2][0]; state[2][0]=state[2][2]; state[2][2]=tmp;
    tmp = state[2][1]; state[2][1]=state[2][3]; state[2][3]=tmp;
    tmp = state[3][0]; state[3][0]=state[3][1]; state[3][1]=state[3][2]; state[3][2]=state[3][3]; state[3][3]=tmp;
}

static void mix_columns(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
#pragma HLS UNROLL
        uint8_t a0 = state[0][i], a1 = state[1][i], a2 = state[2][i], a3 = state[3][i];
        state[0][i] = galois_mul(a0,2) ^ galois_mul(a1,3) ^ a2 ^ a3;
        state[1][i] = a0 ^ galois_mul(a1,2) ^ galois_mul(a2,3) ^ a3;
        state[2][i] = a0 ^ a1 ^ galois_mul(a2,2) ^ galois_mul(a3,3);
        state[3][i] = galois_mul(a0,3) ^ a1 ^ a2 ^ galois_mul(a3,2);
    }
}

static void inv_mix_columns(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
#pragma HLS UNROLL
        uint8_t a0 = state[0][i], a1 = state[1][i], a2 = state[2][i], a3 = state[3][i];
        state[0][i] = galois_mul(a0,0x0e) ^ galois_mul(a1,0x0b) ^ galois_mul(a2,0x0d) ^ galois_mul(a3,0x09);
        state[1][i] = galois_mul(a0,0x09) ^ galois_mul(a1,0x0e) ^ galois_mul(a2,0x0b) ^ galois_mul(a3,0x0d);
        state[2][i] = galois_mul(a0,0x0d) ^ galois_mul(a1,0x09) ^ galois_mul(a2,0x0e) ^ galois_mul(a3,0x0b);
        state[3][i] = galois_mul(a0,0x0b) ^ galois_mul(a1,0x0d) ^ galois_mul(a2,0x09) ^ galois_mul(a3,0x0e);
    }
}

static void key_expansion(uint8_t key[4][4], uint8_t round_keys[11][4][4]) {
#pragma HLS INLINE off
    uint32_t w[44], temp;
    for (int i = 0; i < 4; i++) {
#pragma HLS UNROLL
        w[i] = ((uint32_t)key[0][i]<<24) | ((uint32_t)key[1][i]<<16)
             | ((uint32_t)key[2][i]<<8 ) |  key[3][i];
    }
    for (int i = 4; i < 44; i++) {
#pragma HLS PIPELINE II=1
        temp = w[i-1];
        if (i % 4 == 0) {
            temp = (temp<<8)|(temp>>24);
            temp = ((uint32_t)sbox[(temp>>24)&0xFF]<<24)
                 | ((uint32_t)sbox[(temp>>16)&0xFF]<<16)
                 | ((uint32_t)sbox[(temp>>8 )&0xFF]<<8 )
                 |  sbox[temp&0xFF];
            temp ^= ((uint32_t)Rcon[i/4]<<24);
        }
        w[i] = w[i-4] ^ temp;
    }
    for (int r = 0; r < 11; r++) {
#pragma HLS UNROLL
        for (int c = 0; c < 4; c++) {
#pragma HLS UNROLL
            uint32_t word = w[r*4 + c];
            round_keys[r][0][c] = (word>>24)&0xFF;
            round_keys[r][1][c] = (word>>16)&0xFF;
            round_keys[r][2][c] = (word>>8 )&0xFF;
            round_keys[r][3][c] =  word    &0xFF;
        }
    }
}

extern "C" void aes_encrypt_block(uint32_t input[4], uint32_t key[4], uint32_t output[4]) {
#pragma HLS INLINE off
    uint8_t state[4][4], ks[4][4], round_keys[11][4][4];
    // --- FIX: Proper mapping from input[4] to state[4][4] (column-major, big-endian) ---
    for (int c = 0; c < 4; c++) {
        state[0][c] = (input[c] >> 24) & 0xFF;
        state[1][c] = (input[c] >> 16) & 0xFF;
        state[2][c] = (input[c] >> 8 ) & 0xFF;
        state[3][c] =  input[c]        & 0xFF;
        ks[0][c]    = (key[c] >> 24) & 0xFF;
        ks[1][c]    = (key[c] >> 16) & 0xFF;
        ks[2][c]    = (key[c] >> 8 ) & 0xFF;
        ks[3][c]    =  key[c]        & 0xFF;
    }
    key_expansion(ks, round_keys);
    add_round_key(state, round_keys[0]);
    for (int round = 1; round <= 9; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys[round]);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys[10]);
    for (int c = 0; c < 4; c++) {
        output[c] = (state[0][c]<<24) | (state[1][c]<<16) | (state[2][c]<<8) | state[3][c];
    }
}

extern "C" void aes_decrypt_block(uint32_t input[4], uint32_t key[4], uint32_t output[4]) {
#pragma HLS INLINE off
    uint8_t state[4][4], ks[4][4], round_keys[11][4][4];
    // --- FIX: Proper mapping from input[4] to state[4][4] (column-major, big-endian) ---
    for (int c = 0; c < 4; c++) {
        state[0][c] = (input[c] >> 24) & 0xFF;
        state[1][c] = (input[c] >> 16) & 0xFF;
        state[2][c] = (input[c] >> 8 ) & 0xFF;
        state[3][c] =  input[c]        & 0xFF;
        ks[0][c]    = (key[c] >> 24) & 0xFF;
        ks[1][c]    = (key[c] >> 16) & 0xFF;
        ks[2][c]    = (key[c] >> 8 ) & 0xFF;
        ks[3][c]    =  key[c]        & 0xFF;
    }
    key_expansion(ks, round_keys);
    add_round_key(state, round_keys[10]);
    for (int round = 9; round >= 1; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, round_keys[round]);
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, round_keys[0]);
    for (int c = 0; c < 4; c++) {
        output[c] = (state[0][c]<<24) | (state[1][c]<<16) | (state[2][c]<<8) | state[3][c];
    }
}

// ------------------------------------------------------------------------
// Pipeline Stages
// ------------------------------------------------------------------------

struct FetchReg  { bool valid; uint32_t block_addr; uint32_t block_data[4]; };
struct DecryptReg{ bool valid; uint32_t block_addr; uint32_t decr_block[4]; int instr_index; };
struct DecodeReg {
    bool valid;
    uint32_t instr, word_addr, rs_val, rt_val;
    uint32_t rs_idx, rt_idx;
    uint8_t a_sel, b_sel;
    bool predicted_taken;
    uint32_t predicted_block_addr;
    uint32_t fallthrough_block_addr;
    bool is_control;
};
struct ExecReg {
    bool valid;
    uint32_t alu_result, instr;
    uint32_t rt_forward_val;
    bool taken_branch;
    uint32_t new_block_addr;
    bool predicted_taken;
    uint32_t predicted_block_addr;
    uint32_t fallthrough_block_addr;
    bool is_control;
    bool control_mispredict;
    uint32_t recovery_block_addr;
};
struct MemReg    { bool valid; uint32_t alu_result, instr, mem_read_val; };
struct WbReg     { bool valid; uint32_t final_val, instr; };

static FetchReg   fetch_reg;
static DecryptReg decr_reg;
static DecodeReg  decode_reg;

static inline void invalidateFrontendOnTextWrite(uint32_t word_addr) {
    (void)word_addr;
    // Flush frontend state while preserving the current block progression.
    fetch_reg.valid  = false;
    decr_reg.valid   = false;
    decode_reg.valid = false;
}
static ExecReg    exec_reg;
static MemReg     mem_reg;
static WbReg      wb_reg;

static uint32_t pipeline_stall_count = 0;
static uint32_t branch_prediction_count = 0;
static uint32_t branch_mispredict_count = 0;

static constexpr uint32_t MIPS_OP_SPECIAL = 0x00u;
static constexpr uint32_t MIPS_OP_J       = 0x02u;
static constexpr uint32_t MIPS_OP_BEQ     = 0x04u;
static constexpr uint32_t MIPS_OP_BNE     = 0x05u;
static constexpr uint32_t MIPS_OP_ADDI    = 0x08u;
static constexpr uint32_t MIPS_OP_ORI     = 0x0Du;
static constexpr uint32_t MIPS_OP_LUI     = 0x0Fu;
static constexpr uint32_t MIPS_OP_LW      = 0x23u;
static constexpr uint32_t MIPS_OP_SW      = 0x2Bu;

static constexpr uint32_t MIPS_FUNCT_SLL  = 0x00u;
static constexpr uint32_t MIPS_FUNCT_SRL  = 0x02u;
static constexpr uint32_t MIPS_FUNCT_MULT = 0x18u;
static constexpr uint32_t MIPS_FUNCT_ADD  = 0x20u;
static constexpr uint32_t MIPS_FUNCT_SUB  = 0x22u;
static constexpr uint32_t MIPS_FUNCT_AND  = 0x24u;
static constexpr uint32_t MIPS_FUNCT_OR   = 0x25u;
static constexpr uint32_t MIPS_FUNCT_XOR  = 0x26u;
static constexpr uint32_t MIPS_FUNCT_AESENC = 0x3Au;
static constexpr uint32_t MIPS_FUNCT_AESDEC = 0x3Bu;

static inline uint32_t mips_opcode(uint32_t instr) { return (instr >> 26) & 0x3Fu; }
static inline uint32_t mips_rs(uint32_t instr)     { return (instr >> 21) & 0x1Fu; }
static inline uint32_t mips_rt(uint32_t instr)     { return (instr >> 16) & 0x1Fu; }
static inline uint32_t mips_rd(uint32_t instr)     { return (instr >> 11) & 0x1Fu; }
static inline uint32_t mips_shamt(uint32_t instr)  { return (instr >> 6) & 0x1Fu; }
static inline uint32_t mips_funct(uint32_t instr)  { return instr & 0x3Fu; }
static inline uint32_t mips_imm(uint32_t instr)    { return instr & 0xFFFFu; }
static inline int32_t  mips_simm(uint32_t instr)   { return (int32_t)(int16_t)(instr & 0xFFFFu); }
static inline uint32_t mips_target(uint32_t instr) { return instr & 0x03FFFFFFu; }

static bool isMipsRWriteFunct(uint32_t funct) {
    switch (funct) {
        case MIPS_FUNCT_ADD:
        case MIPS_FUNCT_SUB:
        case MIPS_FUNCT_AND:
        case MIPS_FUNCT_OR:
        case MIPS_FUNCT_XOR:
        case MIPS_FUNCT_SLL:
        case MIPS_FUNCT_SRL:
        case MIPS_FUNCT_MULT:
        case MIPS_FUNCT_AESENC:
        case MIPS_FUNCT_AESDEC:
            return true;
        default:
            return false;
    }
}

static bool isWriteInstruction(uint32_t instr) {
#pragma HLS INLINE
    uint32_t op = mips_opcode(instr);
    if (op == MIPS_OP_SPECIAL) {
        return isMipsRWriteFunct(mips_funct(instr));
    }

    switch (op) {
        case MIPS_OP_LW:
        case MIPS_OP_ADDI:
        case MIPS_OP_ORI:
        case MIPS_OP_LUI:
            return true;
        default:
            return false;
    }
}

static uint32_t getDestReg(uint32_t instr) {
#pragma HLS INLINE
    uint32_t op = mips_opcode(instr);
    if (op == MIPS_OP_SPECIAL) {
        return isMipsRWriteFunct(mips_funct(instr)) ? mips_rd(instr) : 0u;
    }

    if (op == MIPS_OP_LW || op == MIPS_OP_ADDI || op == MIPS_OP_ORI || op == MIPS_OP_LUI) {
        return mips_rt(instr);
    }

    return 0u;
}

static bool isLoadInstruction(uint32_t instr) {
#pragma HLS INLINE
    return mips_opcode(instr) == MIPS_OP_LW;
}

static bool isControlInstruction(uint32_t instr) {
#pragma HLS INLINE
    uint32_t op = mips_opcode(instr);
    return (op == MIPS_OP_BEQ || op == MIPS_OP_BNE || op == MIPS_OP_J);
}

static uint32_t computeJumpTargetBlock(uint32_t instr) {
#pragma HLS INLINE
    uint32_t target_word = mips_target(instr);
    if (target_word >= kMarsTextBaseWord) {
        target_word = kTextStartAddr + (target_word - kMarsTextBaseWord);
    }
    return target_word / INSTRS_PER_BLOCK;
}

static uint32_t computeBranchTargetBlock(uint32_t word_addr, int32_t simm) {
#pragma HLS INLINE
    int32_t next_word = (int32_t)word_addr + 1 + simm;
    if (next_word < 0) next_word = 0;
    return ((uint32_t)next_word) / INSTRS_PER_BLOCK;
}

static bool branchPredictTaken(uint32_t instr) {
#pragma HLS INLINE
    uint32_t op = mips_opcode(instr);
    // Basic, deterministic predictor: unconditional jumps are predicted taken;
    // conditional branches use static predict-not-taken and are recovered by flush.
    return op == MIPS_OP_J;
}

static void getSourceRegs(uint32_t instr, uint32_t &rs, uint32_t &rt) {
#pragma HLS INLINE
    rs = 0u;
    rt = 0u;

    uint32_t op = mips_opcode(instr);
    if (op == MIPS_OP_SPECIAL) {
        uint32_t funct = mips_funct(instr);
        switch (funct) {
            case MIPS_FUNCT_ADD:
            case MIPS_FUNCT_SUB:
            case MIPS_FUNCT_AND:
            case MIPS_FUNCT_OR:
            case MIPS_FUNCT_XOR:
            case MIPS_FUNCT_MULT:
            case MIPS_FUNCT_AESENC:
                rs = mips_rs(instr);
                rt = mips_rt(instr);
                return;
            case MIPS_FUNCT_AESDEC:
                rs = 0u;
                rt = 0u;
                return;
            case MIPS_FUNCT_SLL:
            case MIPS_FUNCT_SRL:
                rs = 0u;
                rt = mips_rt(instr);
                return;
            default:
                return;
        }
    }

    switch (op) {
        case MIPS_OP_LW:
        case MIPS_OP_ADDI:
        case MIPS_OP_ORI:
            rs = mips_rs(instr);
            rt = 0u;
            return;
        case MIPS_OP_SW:
        case MIPS_OP_BEQ:
        case MIPS_OP_BNE:
            rs = mips_rs(instr);
            rt = mips_rt(instr);
            return;
        default:
            return;
    }
}

static bool checkDataHazard(uint32_t decode_instr,
                            uint32_t exec_instr,
                            uint32_t mem_instr,
                            uint8_t &a_sel,
                            uint8_t &b_sel) {
#pragma HLS INLINE off
    uint32_t d_rs, d_rt;
    getSourceRegs(decode_instr, d_rs, d_rt);
    a_sel = b_sel = 0;
    bool must_stall = false;

    // EX-stage producer: ALU results can be forwarded, but a load's data is
    // not available until the MEM stage. That exact load-use case inserts a
    // one-cycle decode stall.
    if (exec_reg.valid && isWriteInstruction(exec_instr)) {
        uint32_t exd = getDestReg(exec_instr);
        if (exd && (d_rs == exd || d_rt == exd)) {
            if (isLoadInstruction(exec_instr)) {
                must_stall = true;
            } else {
                if (d_rs == exd) a_sel = 1;
                if (d_rt == exd) b_sel = 1;
            }
        }
    }

    // MEM/WB-stage producer: final ALU or load value can be forwarded.
    if (mem_reg.valid && isWriteInstruction(mem_instr)) {
        uint32_t md = getDestReg(mem_instr);
        if (md && !a_sel && d_rs == md) a_sel = 2;
        if (md && !b_sel && d_rt == md) b_sel = 2;
    }

    return must_stall;
}

static void stage_fetch() {
#pragma HLS INLINE off
    if (!fetch_reg.valid) {
        if (!key_valid) {
            uint32_t extracted_key[4] = {0, 0, 0, 0};
            int rc = extract_key_from_large_block(instr_layer, extracted_key);
            if (rc != 0 || stackedMemory.isSecurityLocked()) {
                key_check_failed = true;
                secure_zero_words(extracted_key, 4);
                secure_zero_words(runtime_app_key, 4);
                return;
            }

            for (int i = 0; i < 4; ++i) {
                runtime_app_key[i] = extracted_key[i];
            }
            key_check_failed = false;
            key_valid = true;
            secure_zero_words(extracted_key, 4);
        }

        uint32_t text_start_block = secure_runtime_region_valid
            ? (secure_runtime_text_start_addr / INSTRS_PER_BLOCK)
            : kTextStartBlock;
        uint32_t text_end_block = secure_runtime_region_valid
            ? ((secure_runtime_text_enc_end + INSTRS_PER_BLOCK - 1) / INSTRS_PER_BLOCK)
            : (MEM_SIZE / INSTRS_PER_BLOCK);

        if (fetch_reg.block_addr < text_start_block) {
            fetch_reg.block_addr = text_start_block;
        }
        if (fetch_reg.block_addr >= text_end_block) {
            return;
        }

        uint32_t block[INSTRS_PER_BLOCK];
        icache_read_block(fetch_reg.block_addr, block);
        for (int i = 0; i < INSTRS_PER_BLOCK; i++) {
            fetch_reg.block_data[i] = block[i];
        }
        fetch_reg.valid = true;
    }
}

static void stage_decrypt() {
#pragma HLS INLINE off
    if (fetch_reg.valid && !decr_reg.valid) {
        uint32_t out[4];
        uint32_t text_start_block = secure_runtime_region_valid
            ? (secure_runtime_text_start_addr / INSTRS_PER_BLOCK)
            : kTextStartBlock;

        // The encryptor writes ciphertext for .text blocks (from text_start_block and above).
         #if !defined(__SYNTHESIS__) && TRACE_PIPELINE
        printf("[F] L%u B%u ENC: %08X %08X %08X %08X\n",
               instr_layer, fetch_reg.block_addr,
               fetch_reg.block_data[0], fetch_reg.block_data[1], fetch_reg.block_data[2], fetch_reg.block_data[3]);
        #endif
        if (fetch_reg.block_addr >= text_start_block) {
            aes_decrypt_block(fetch_reg.block_data, runtime_app_key, out);
        } else {
            for (int i = 0; i < 4; i++) out[i] = fetch_reg.block_data[i];
        }
         #if !defined(__SYNTHESIS__) && TRACE_PIPELINE
        printf("[D] L%u B%u DEC: %08X %08X %08X %08X\n",
               instr_layer, fetch_reg.block_addr,
               out[0], out[1], out[2], out[3]);
        #endif

        for (int i = 0; i < 4; i++) decr_reg.decr_block[i] = out[i];
        decr_reg.valid       = true;
        decr_reg.block_addr  = fetch_reg.block_addr;
        decr_reg.instr_index = 0;
        fetch_reg.valid      = false;
        fetch_reg.block_addr++;
    }
}

static void stage_decode(bool stall) {
#pragma HLS INLINE off
    if (!stall && decr_reg.valid && !decode_reg.valid) {
        uint32_t curr_idx = (uint32_t)decr_reg.instr_index;
        uint32_t instr = decr_reg.decr_block[curr_idx];
        uint32_t word_addr = decr_reg.block_addr * INSTRS_PER_BLOCK + curr_idx;
        uint32_t rs, rt; getSourceRegs(instr, rs, rt);
        uint8_t a_sel, b_sel;
        checkDataHazard(instr, exec_reg.instr, mem_reg.instr, a_sel, b_sel);

        uint32_t opcode = mips_opcode(instr);
        int32_t simm = mips_simm(instr);
        bool is_ctrl = isControlInstruction(instr);
        bool pred_taken = branchPredictTaken(instr);
        uint32_t pred_block = (word_addr + 1u) / INSTRS_PER_BLOCK;
        if (opcode == MIPS_OP_J) {
            pred_block = computeJumpTargetBlock(instr);
        } else if (opcode == MIPS_OP_BEQ || opcode == MIPS_OP_BNE) {
            uint32_t target_block = computeBranchTargetBlock(word_addr, simm);
            pred_block = pred_taken ? target_block : ((word_addr + 1u) / INSTRS_PER_BLOCK);
        }

        decode_reg.valid  = true;
        decode_reg.instr  = instr;
        decode_reg.word_addr = word_addr;
        decode_reg.rs_val = reg_file[rs];
        decode_reg.rt_val = reg_file[rt];
        decode_reg.rs_idx = rs;
        decode_reg.rt_idx = rt;
        decode_reg.a_sel  = a_sel;
        decode_reg.b_sel  = b_sel;
        decode_reg.is_control = is_ctrl;
        decode_reg.predicted_taken = pred_taken;
        decode_reg.predicted_block_addr = pred_block;
        decode_reg.fallthrough_block_addr = (word_addr + 1u) / INSTRS_PER_BLOCK;

        if (is_ctrl) {
            branch_prediction_count++;
        }

        decr_reg.instr_index++;
        if (decr_reg.instr_index >= INSTRS_PER_BLOCK) {
            decr_reg.valid = false;
        }

        // Basic branch prediction: unconditional jumps redirect at decode.
        // Conditional branches intentionally use static predict-not-taken.
        if (pred_taken) {
            fetch_reg.valid = false;
            decr_reg.valid = false;
            fetch_reg.block_addr = pred_block;
        }
    }
}

static void stage_execute() {
#pragma HLS INLINE off
    if (decode_reg.valid && !exec_reg.valid) {
        uint32_t instr = decode_reg.instr;
        uint32_t opcode = mips_opcode(instr);
        uint32_t funct  = mips_funct(instr);
        uint32_t rs_val = decode_reg.rs_val;
        uint32_t rt_val = decode_reg.rt_val;

        // Dynamic execute-time forwarding. The scheduler calls stage_memory()
        // before stage_execute(), so the immediately preceding producer is
        // visible in mem_reg, while the producer two cycles back is visible in
        // wb_reg. This avoids stale selector timing and supports ALU, load, and
        // store-data dependencies.
        bool rs_forwarded = false;
        bool rt_forwarded = false;
        if (mem_reg.valid && isWriteInstruction(mem_reg.instr)) {
            uint32_t md = getDestReg(mem_reg.instr);
            if (md && decode_reg.rs_idx == md) { rs_val = mem_reg.mem_read_val; rs_forwarded = true; perf_forward_mem++; }
            if (md && decode_reg.rt_idx == md) { rt_val = mem_reg.mem_read_val; rt_forwarded = true; perf_forward_mem++; }
        }
        if (wb_reg.valid && isWriteInstruction(wb_reg.instr)) {
            uint32_t wd = getDestReg(wb_reg.instr);
            if (wd && !rs_forwarded && decode_reg.rs_idx == wd) { rs_val = wb_reg.final_val; perf_forward_wb++; }
            if (wd && !rt_forwarded && decode_reg.rt_idx == wd) { rt_val = wb_reg.final_val; perf_forward_wb++; }
        }
        if (opcode == MIPS_OP_SW && rt_forwarded) {
            perf_store_data_forwards++;
        }
        uint32_t alu_res = 0;
        bool     br      = false;
        uint32_t nb      = 0;
        int32_t simm = mips_simm(instr);
        uint32_t uimm = mips_imm(instr);

        switch(opcode) {
            case MIPS_OP_SPECIAL:
                switch (funct) {
                    case MIPS_FUNCT_ADD:  alu_res = rs_val + rt_val; break;
                    case MIPS_FUNCT_SUB:  alu_res = rs_val - rt_val; break;
                    case MIPS_FUNCT_AND:  alu_res = rs_val & rt_val; break;
                    case MIPS_FUNCT_OR:   alu_res = rs_val | rt_val; break;
                    case MIPS_FUNCT_XOR:  alu_res = rs_val ^ rt_val; break;
                    case MIPS_FUNCT_SLL:  alu_res = rt_val << (mips_shamt(instr) & 0x1Fu); break;
                    case MIPS_FUNCT_SRL:  alu_res = rt_val >> (mips_shamt(instr) & 0x1Fu); break;
                    case MIPS_FUNCT_MULT: alu_res = rs_val * rt_val; break;
                    case MIPS_FUNCT_AESENC: {
                        perf_aes_instructions++;
                        uint32_t in[4] = {
                            rs_val,
                            rt_val,
                            rs_val,
                            rt_val
                        };
                        uint32_t out[4];
                        aes_encrypt_block(in, runtime_app_key, out);
                        for (int i = 0; i < 4; ++i) copro_reg[i] = out[i];
                        alu_res = out[0];
                        break;
                    }
                    case MIPS_FUNCT_AESDEC: {
                        perf_aes_instructions++;
                        uint32_t out[4];
                        aes_decrypt_block(copro_reg, runtime_app_key, out);
                        alu_res = out[0];
                        break;
                    }
                    default: break;
                }
                break;
            case MIPS_OP_LW:
            case MIPS_OP_SW:
            case MIPS_OP_ADDI:
                alu_res = rs_val + (uint32_t)simm;
                break;
            case MIPS_OP_ORI:
                alu_res = rs_val | uimm;
                break;
            case MIPS_OP_LUI:
                alu_res = uimm << 16;
                break;
            case MIPS_OP_BEQ:
                if (rs_val == rt_val) {
                    br = true;
                    nb = computeBranchTargetBlock(decode_reg.word_addr, simm);
                }
                break;
            case MIPS_OP_BNE:
                if (rs_val != rt_val) {
                    br = true;
                    nb = computeBranchTargetBlock(decode_reg.word_addr, simm);
                }
                break;
            case MIPS_OP_J:
                br = true;
                nb = computeJumpTargetBlock(instr);
                break;
            default:
                break;
        }
        uint32_t actual_block = br ? nb : decode_reg.fallthrough_block_addr;
        uint32_t predicted_block = decode_reg.predicted_taken
            ? decode_reg.predicted_block_addr
            : decode_reg.fallthrough_block_addr;
        bool mispredict = decode_reg.is_control && (actual_block != predicted_block);
        if (mispredict) {
            branch_mispredict_count++;
        }

        exec_reg.valid         = true;
        exec_reg.alu_result    = alu_res;
        exec_reg.instr         = decode_reg.instr;
        exec_reg.rt_forward_val= rt_val;
        exec_reg.taken_branch  = br;
        exec_reg.new_block_addr= nb;
        exec_reg.predicted_taken = decode_reg.predicted_taken;
        exec_reg.predicted_block_addr = decode_reg.predicted_block_addr;
        exec_reg.fallthrough_block_addr = decode_reg.fallthrough_block_addr;
        exec_reg.is_control    = decode_reg.is_control;
        exec_reg.control_mispredict = mispredict;
        exec_reg.recovery_block_addr = actual_block;
        decode_reg.valid       = false;
    }
}

static bool translateDataAddress(uint32_t eff_addr, uint32_t &word_addr) {
    if (eff_addr < MEM_SIZE) {
        word_addr = eff_addr;
        return true;
    }

    if ((eff_addr & 0x3u) != 0u) {
        return false;
    }

    if (eff_addr >= kMarsDataBaseByte) {
        uint32_t data_base_word = secure_runtime_region_valid ? secure_runtime_data_start_addr : secure_data_start_addr;
        uint32_t offs_words = (eff_addr - kMarsDataBaseByte) >> 2;
        uint32_t mapped = data_base_word + offs_words;
        if (mapped < MEM_SIZE) {
            word_addr = mapped;
            return true;
        }
    }

    uint32_t as_word = eff_addr >> 2;
    if (as_word < MEM_SIZE) {
        word_addr = as_word;
        return true;
    }

    return false;
}

static bool secure_is_encrypted_data_word(uint32_t word_addr) {
    uint32_t start = secure_runtime_region_valid ? secure_runtime_data_start_addr : secure_data_start_addr;
    uint32_t end   = secure_runtime_region_valid ? secure_runtime_data_enc_end   : secure_data_enc_end;
    uint32_t flags = secure_runtime_region_valid ? secure_runtime_data_flags      : secure_data_flags;

    if ((flags & SEC_DATA_FLAG_ENCRYPTED) == 0u) return false;
    if (start >= end) return false;
    return (word_addr >= start && word_addr < end);
}

static bool secure_is_data_word(uint32_t word_addr) {
    uint32_t start = secure_runtime_region_valid ? secure_runtime_data_start_addr : secure_data_start_addr;
    uint32_t end   = secure_runtime_region_valid ? secure_runtime_data_enc_end   : secure_data_enc_end;

    if (start >= end) return false;
    return (word_addr >= start && word_addr < end);
}

static bool secure_is_text_word(uint32_t word_addr) {
    uint32_t start = secure_runtime_region_valid ? secure_runtime_text_start_addr : secure_text_start_addr;
    uint32_t end   = secure_runtime_region_valid ? secure_runtime_text_enc_end    : secure_text_enc_end;

    if (start >= end) return false;
    return (word_addr >= start && word_addr < end);
}

static uint32_t secure_read_encrypted_data_word(uint32_t word_addr) {
    uint32_t base = (word_addr / INSTRS_PER_BLOCK) * INSTRS_PER_BLOCK;
    uint32_t cipher[INSTRS_PER_BLOCK] = {0u, 0u, 0u, 0u};
    uint32_t plain[INSTRS_PER_BLOCK]  = {0u, 0u, 0u, 0u};
    uint32_t result = 0u;

    if ((base + INSTRS_PER_BLOCK) > (uint32_t)stackedMemory.getNumWords()) {
        return 0u;
    }

    for (int i = 0; i < INSTRS_PER_BLOCK; ++i) {
        cipher[i] = stackedMemory.rawRead(data_layer, base + (uint32_t)i);
    }

    aes_decrypt_block(cipher, runtime_app_key, plain);
    result = plain[word_addr % INSTRS_PER_BLOCK];

    secure_zero_words(cipher, INSTRS_PER_BLOCK);
    secure_zero_words(plain, INSTRS_PER_BLOCK);
    return result;
}

static void secure_write_encrypted_data_word(uint32_t word_addr, uint32_t value) {
    uint32_t base = (word_addr / INSTRS_PER_BLOCK) * INSTRS_PER_BLOCK;
    uint32_t cipher[INSTRS_PER_BLOCK]   = {0u, 0u, 0u, 0u};
    uint32_t plain[INSTRS_PER_BLOCK]    = {0u, 0u, 0u, 0u};
    uint32_t recipher[INSTRS_PER_BLOCK] = {0u, 0u, 0u, 0u};

    if ((base + INSTRS_PER_BLOCK) > (uint32_t)stackedMemory.getNumWords()) {
        return;
    }

    for (int i = 0; i < INSTRS_PER_BLOCK; ++i) {
        cipher[i] = stackedMemory.rawRead(data_layer, base + (uint32_t)i);
    }

    aes_decrypt_block(cipher, runtime_app_key, plain);
    plain[word_addr % INSTRS_PER_BLOCK] = value;
    aes_encrypt_block(plain, runtime_app_key, recipher);

    for (int i = 0; i < INSTRS_PER_BLOCK; ++i) {
        uint32_t addr = base + (uint32_t)i;
        stackedMemory.protectedWrite(data_layer, addr, recipher[i]);

        uint32_t index = 0, tag = 0;
        dcache_get_index_tag(addr, index, tag);
        if (dcache_valid[index] && dcache_tag[index] == tag) {
            dcache_valid[index] = false;
        }
    }

    secure_zero_words(cipher, INSTRS_PER_BLOCK);
    secure_zero_words(plain, INSTRS_PER_BLOCK);
    secure_zero_words(recipher, INSTRS_PER_BLOCK);
}

static void stage_memory() {
#pragma HLS INLINE off
    if (exec_reg.valid && !mem_reg.valid) {
        uint32_t opcode = mips_opcode(exec_reg.instr);
        uint32_t val    = 0;
        uint32_t addr   = exec_reg.alu_result;
        uint32_t word_addr = 0;
        switch(opcode) {
            case MIPS_OP_LW:
                if (translateDataAddress(addr, word_addr)) {
                    if (!secure_is_data_word(word_addr)) {
                        stackedMemory.lockSecurity("DATA READ");
                        val = 0u;
                        break;
                    }
                    if (secure_is_encrypted_data_word(word_addr)) {
                        val = secure_read_encrypted_data_word(word_addr);
                    } else {
                        val = dcache_read(word_addr);
                    }
                }
                break;
            case MIPS_OP_SW:
                if (translateDataAddress(addr, word_addr)) {
#if CRYPTO3D_STRICT_TEXT_WRITE_PROTECT
                    if (word_addr < SEC_HDR_WORDS || secure_is_text_word(word_addr) || !secure_is_data_word(word_addr)) {
                        stackedMemory.lockSecurity("DATA WRITE");
                        break;
                    }
#endif
                    uint32_t store_value = exec_reg.rt_forward_val;
                    if (secure_is_encrypted_data_word(word_addr)) {
                        secure_write_encrypted_data_word(word_addr, store_value);
                    } else {
                        dcache_write(word_addr, store_value);
                        invalidateFrontendOnTextWrite(word_addr);
                    }
                }
                break;
            default: break;
        }
        mem_reg.valid        = true;
        mem_reg.alu_result   = exec_reg.alu_result;
        mem_reg.instr        = exec_reg.instr;
        // Carry forward the final value that WB would use, so MEM forwarding is correct.
        if (opcode == MIPS_OP_LW) {
            mem_reg.mem_read_val = val;
        } else {
            mem_reg.mem_read_val = exec_reg.alu_result;
        }
        exec_reg.valid       = false;
    }
}

static void stage_writeback() {
#pragma HLS INLINE off
    if (mem_reg.valid && !wb_reg.valid) {
        uint32_t opcode = mips_opcode(mem_reg.instr);
        uint32_t funct  = mips_funct(mem_reg.instr);
        uint32_t rd     = mips_rd(mem_reg.instr);
        uint32_t rt     = mips_rt(mem_reg.instr);
        uint32_t fv     = 0;
        switch(opcode) {
            case MIPS_OP_LW:
                fv = mem_reg.mem_read_val;
                if (rt) reg_file[rt] = fv;
                retired_instructions++;
                break;
            case MIPS_OP_ADDI:
            case MIPS_OP_ORI:
            case MIPS_OP_LUI:
                fv = mem_reg.alu_result;
                if (rt) reg_file[rt] = fv;
                retired_instructions++;
                break;
            case MIPS_OP_SPECIAL:
                if (!isMipsRWriteFunct(funct)) break;
                fv = mem_reg.alu_result;
                if (rd) reg_file[rd] = fv;
                retired_instructions++;
                break;
            default: break;
        }
        wb_reg.valid    = true;
        wb_reg.final_val= fv;
        wb_reg.instr    = mem_reg.instr;
        mem_reg.valid   = false;
    }
}

extern "C" uint32_t Crypto3DStackCPU_get_perf_counter(uint32_t counter_id) {
    switch (counter_id) {
        case CRYPTO3D_PERF_CYCLES:              return perf_cycle_count;
        case CRYPTO3D_PERF_RETIRED:             return retired_instructions;
        case CRYPTO3D_PERF_STALLS:              return pipeline_stall_count;
        case CRYPTO3D_PERF_LOAD_USE_STALLS:     return perf_load_use_stalls;
        case CRYPTO3D_PERF_BRANCH_PREDICTIONS:  return branch_prediction_count;
        case CRYPTO3D_PERF_BRANCH_MISPREDICTS:  return branch_mispredict_count;
        case CRYPTO3D_PERF_ICACHE_HITS:         return perf_icache_hits;
        case CRYPTO3D_PERF_ICACHE_MISSES:       return perf_icache_misses;
        case CRYPTO3D_PERF_DCACHE_HITS:         return perf_dcache_hits;
        case CRYPTO3D_PERF_DCACHE_MISSES:       return perf_dcache_misses;
        case CRYPTO3D_PERF_FORWARD_MEM:         return perf_forward_mem;
        case CRYPTO3D_PERF_FORWARD_WB:          return perf_forward_wb;
        case CRYPTO3D_PERF_STORE_DATA_FORWARDS: return perf_store_data_forwards;
        case CRYPTO3D_PERF_AES_INSTRUCTIONS:    return perf_aes_instructions;
        default:                                return 0u;
    }
}

// ------------------------------------------------------------------------
// Top Function for HLS
// ------------------------------------------------------------------------


extern "C" void Crypto3DStackCPU_top(volatile uint32_t* image,
                                       uint32_t word_count,
                                       volatile uint32_t* status_word)
{
#pragma HLS INTERFACE m_axi     port=image       offset=slave bundle=gmem    depth=MEM_SIZE
#pragma HLS INTERFACE m_axi     port=status_word offset=slave bundle=gmem    depth=1
#pragma HLS INTERFACE s_axilite port=image                   bundle=control
#pragma HLS INTERFACE s_axilite port=word_count              bundle=control
#pragma HLS INTERFACE s_axilite port=status_word             bundle=control
#pragma HLS INTERFACE s_axilite port=return                  bundle=control

    uint32_t io_words = word_count;
    if (io_words == 0u || io_words > MEM_SIZE) {
        io_words = MEM_SIZE;
    }

    // New host image should start from a clean security-lock state.
    if (stackedMemory.isSecurityLocked()) {
        stackedMemory.clearSecurityLockdown();
    }

    if (image != nullptr) {
        for (uint32_t i = 0; i < io_words; ++i) {
#pragma HLS LOOP_TRIPCOUNT min=1 max=MEM_SIZE
            uint32_t value = image[i];
            if (i < SEC_HDR_WORDS) {
                stackedMemory.protectedWrite(0, i, value);
            } else {
                stackedMemory.write(0, i, value);
            }
        }

        for (uint32_t i = io_words; i < MEM_SIZE; ++i) {
#pragma HLS LOOP_TRIPCOUNT min=1 max=MEM_SIZE
            if (i < SEC_HDR_WORDS) {
                stackedMemory.protectedWrite(0, i, 0u);
            } else {
                stackedMemory.write(0, i, 0u);
            }
        }
    }

    const uint32_t start_block = kTextStartBlock;
    const uint32_t num_cycles  = 2000;

    retired_instructions = 0;
    pipeline_stall_count = 0;
    branch_prediction_count = 0;
    branch_mispredict_count = 0;
    perf_cycle_count = 0;
    perf_icache_hits = 0;
    perf_icache_misses = 0;
    perf_dcache_hits = 0;
    perf_dcache_misses = 0;
    perf_forward_mem = 0;
    perf_forward_wb = 0;
    perf_load_use_stalls = 0;
    perf_store_data_forwards = 0;
    perf_aes_instructions = 0;
    // Per-invocation architectural reset. This is essential for repeatable
    // execution: if the top function is called twice (e.g. during HLS CSIM
    // or back-to-back test runs), register file and caches MUST be zeroed
    // so the new image starts from a known-good state.
    for (int r = 0; r < NUM_REGS; r++) {
        reg_file[r] = 0;
    }
    for (int i = 0; i < ICACHE_LINES; i++) {
        iCache_valid[i] = false;
        iCache_tag[i]   = 0;
    }
    for (int i = 0; i < DCACHE_LINES; i++) {
        dcache_valid[i] = false;
        dcache_tag[i]   = 0;
    }
    // Enable secure processing for the validated boot layer (layer 0).
    // The memory model is a 4-layer 3D stack; the default sealed image boots
    // from layer 0 while CPU_set_layers() can select other valid layers.
    stackedMemory.enableProcessingLayer(0);

    // Default validated boot layer selection
    instr_layer = 0;
    data_layer  = 0;
    // Reset pipeline registers
    fetch_reg.valid      = false;
    fetch_reg.block_addr = start_block;
    decr_reg.valid       = false;
    decode_reg.valid     = false;
    exec_reg.valid       = false;
    mem_reg.valid        = false;
    wb_reg.valid         = false;

    // Reset validation flag every time simulation loads new .hex
    key_valid = false;
    key_check_failed = false;
    secure_zero_words(runtime_app_key, 4);
    for (int i = 0; i < 4; ++i) {
        copro_reg[i] = 0u;
    }
    secure_runtime_map_valid = false;
    secure_runtime_region_valid = false;


    // Main execution loop
    for (uint32_t cycle = 0; cycle < num_cycles; cycle++) {
#pragma HLS PIPELINE II=1
        if (key_check_failed || stackedMemory.isSecurityLocked()) {
            break;
        }
        perf_cycle_count++;
        if (wb_reg.valid)       wb_reg.valid = false;
        if (mem_reg.valid)      stage_writeback();
        if (exec_reg.valid) {
            if (exec_reg.control_mispredict) {
                // Recover from static branch-prediction miss.
                decr_reg.valid       = false;
                decode_reg.valid     = false;
                fetch_reg.valid      = false;
                fetch_reg.block_addr = exec_reg.recovery_block_addr;
            }
            stage_memory();
        }
        if (decode_reg.valid)   stage_execute();
        if (decr_reg.valid) {
            uint32_t next_instr = decr_reg.decr_block[decr_reg.instr_index];
            uint8_t a_sel, b_sel;
            bool must_stall = checkDataHazard(next_instr, exec_reg.instr, mem_reg.instr, a_sel, b_sel);
            if (!must_stall) {
                stage_decode(false);
            } else {
                pipeline_stall_count++;
                perf_load_use_stalls++;
            }
        } else {
            stage_decrypt();
        }
        if (!fetch_reg.valid)   stage_fetch();
    }


#if !defined(__SYNTHESIS__) && TRACE_POST_TEXT_DUMP
    if (key_valid) {
        printf("=== POST-EXECUTION DECRYPTED .TEXT DUMP ===\n");
        for (int a = kTextStartAddr; a < (int)stackedMemory.getNumWords(); a += 4) {
            uint32_t enc[4] = {
                stackedMemory.rawRead(instr_layer, a+0),
                stackedMemory.rawRead(instr_layer, a+1),
                stackedMemory.rawRead(instr_layer, a+2),
                stackedMemory.rawRead(instr_layer, a+3),
            };
            uint32_t dec[4];
            aes_decrypt_block(enc, runtime_app_key, dec);
            for (int i=0;i<4;i++) {
                if (dec[i] != 0x00000000)
                    printf("L%u[%03X] = 0x%08X\n", instr_layer, a+i, dec[i]);
            }
        }
    }
#endif

#if CRYPTO3D_ENABLE_OUTPUT_RESEAL
    if (key_valid && !key_check_failed && !stackedMemory.isSecurityLocked()) {
        int reseal_rc = secure_reseal_current_image(0);
        if (reseal_rc != 0) {
            key_check_failed = true;
        }
    }
#endif

    if (image != nullptr) {
        for (uint32_t i = 0; i < io_words; ++i) {
#pragma HLS LOOP_TRIPCOUNT min=1 max=MEM_SIZE
            uint32_t value = (i < SEC_HDR_WORDS)
                ? stackedMemory.protectedRead(0, i)
                : stackedMemory.read(0, i);
            image[i] = value;
        }
    }

    uint32_t status = 0u;
    if (stackedMemory.isSecurityLocked()) status |= 0x00000001u;
    if (key_check_failed)                status |= 0x00000002u;
    status |= ((retired_instructions & 0xFFFFu) << 16);

    if (status_word != nullptr) {
        status_word[0] = status;
    }

    secure_zero_words(runtime_app_key, 4);
    for (int i = 0; i < 4; ++i) {
        copro_reg[i] = 0u;
    }
    key_valid = false;
}
