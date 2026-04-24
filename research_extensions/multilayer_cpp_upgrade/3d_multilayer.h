#ifndef CRYPTO3DSTACKCPU_H
#define CRYPTO3DSTACKCPU_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <iostream>

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
// HLS-compatible static sizes
// ------------------------------------------------------------------------
// Multi-layer 3D stacked-memory abstraction.
// The validated CPU path still boots layer 0 by default, but the memory
// model is now a real fixed-size multi-layer stack.
#define MAX_LAYERS   4
#define MAX_WORDS    1024
#define MAX_LOG_LEN  128

// ------------------------------------------------------------------------
// AES extern declarations
// ------------------------------------------------------------------------
extern "C" void aes_encrypt_block(uint32_t*, uint32_t*, uint32_t*);
extern "C" void aes_decrypt_block(uint32_t*, uint32_t*, uint32_t*);

// ------------------------------------------------------------------------
// Forward declarations (implemented in 3d.cpp)
// ------------------------------------------------------------------------
void invalidateCaches();

// ------------------------------------------------------------------------
// StackedMemory3D Abstraction (Multi-Layer Policy)
// ------------------------------------------------------------------------
class StackedMemory3D {
public:
    static constexpr size_t DEFAULT_LAYER = 0;

private:
    mutable uint32_t lfsr_state = 0xACE1u;

    bool layer_is_encrypted[MAX_LAYERS];
    bool layer_has_hidden_key[MAX_LAYERS];

    bool disable_processing_scramble = false;
    bool tamper_detected = false;
    bool security_lockdown = false;
    uint32_t tamper_events = 0;
    size_t processing_layer = SIZE_MAX;

    // Simulation-only placeholder for the hardware root key.
    // On an FPGA target this MUST be replaced by a non-observable hardware
    // root such as eFuse, PUF-derived key material, battery-backed SRAM, or
    // another tamper-aware on-chip secret. It must not be readable from AXI,
    // JTAG, software, or the external image.
    uint32_t hardware_key = 0xA1B2C3D4u;

    bool isValidLayer(size_t layer) const {
        return layer < num_layers && layer < MAX_LAYERS;
    }

    size_t normalizeLayer(size_t layer) const {
        return isValidLayer(layer) ? layer : DEFAULT_LAYER;
    }

    uint32_t logicalReadNoAccessCheck(size_t layer, size_t addr) const {
        size_t nl = normalizeLayer(layer);
        if (addr >= num_words) return 0xDEADBEEF;

        if (!layer_is_encrypted[nl]) {
            return memory[nl][addr];
        }

        size_t base = (addr / INSTRS_PER_BLOCK) * INSTRS_PER_BLOCK;
        if ((base + INSTRS_PER_BLOCK) > num_words) {
            return 0xDEADBEEF;
        }

        uint32_t in[INSTRS_PER_BLOCK] = {
            memory[nl][base + 0],
            memory[nl][base + 1],
            memory[nl][base + 2],
            memory[nl][base + 3]
        };

        uint32_t key_local[INSTRS_PER_BLOCK] = {
            layer_keys[nl][0],
            layer_keys[nl][1],
            layer_keys[nl][2],
            layer_keys[nl][3]
        };

        uint32_t out[INSTRS_PER_BLOCK];
        aes_decrypt_block(in, key_local, out);

        const uint32_t scramble_key = 0xCAFEBABEu ^ (uint32_t)(nl * 0x9E3779B9u);
        return out[addr % INSTRS_PER_BLOCK] ^ scramble_key;
    }

    static uint32_t mix32(uint32_t x) {
        x ^= x >> 16;
        x *= 0x7FEB352Du;
        x ^= x >> 15;
        x *= 0x846CA68Bu;
        x ^= x >> 16;
        return x;
    }

    uint32_t deriveLayerKeyWord(size_t layer, size_t word) const {
        uint32_t x = hardware_key;
        x ^= 0x9E3779B9u * (uint32_t)(layer + 1u);
        x ^= 0x85EBCA6Bu * (uint32_t)(word + 1u);
        x ^= (uint32_t)(layer << 16) ^ (uint32_t)word;
        return mix32(x);
    }

public:
    // ------------------------------------------------------------------------
    // Member Variables
    // ------------------------------------------------------------------------
    uint32_t layer_keys[MAX_LAYERS][4];
    uint32_t memory[MAX_LAYERS][MAX_WORDS];
    bool     layer_access[MAX_LAYERS];
    char     layer_log[MAX_LAYERS][MAX_LOG_LEN];

    size_t   num_layers = 1;
    size_t   num_words  = 0;

    // ------------------------------------------------------------------------
    // Helpers / Init
    // ------------------------------------------------------------------------
    static void appendLog(char* dst, const char* tag) {
        if (dst == nullptr || tag == nullptr) return;

        size_t len = 0;
        while (len < MAX_LOG_LEN && dst[len] != '\0') {
            len++;
        }

        for (size_t i = 0; tag[i] != '\0' && (len + i) < (MAX_LOG_LEN - 1); i++) {
            dst[len + i] = tag[i];
        }

        dst[MAX_LOG_LEN - 1] = '\0';
    }

    StackedMemory3D(size_t layers, size_t words_per_layer) {
        num_layers = (layers == 0) ? 1 : layers;
        if (num_layers > MAX_LAYERS) {
            num_layers = MAX_LAYERS;
        }

        num_words = (words_per_layer > MAX_WORDS ? MAX_WORDS : words_per_layer);
        num_words = (num_words / INSTRS_PER_BLOCK) * INSTRS_PER_BLOCK;
        if (num_words == 0) {
            num_words = INSTRS_PER_BLOCK;
        }

        for (size_t l = 0; l < MAX_LAYERS; ++l) {
            for (size_t w = 0; w < MAX_WORDS; ++w) {
                memory[l][w] = 0u;
            }

            layer_access[l] = (l < num_layers);
            layer_log[l][0] = '\0';
            layer_is_encrypted[l] = false;
            layer_has_hidden_key[l] = false;
        }

        initLayerKeys();
    }

    void initLayerKeys() {
        for (size_t l = 0; l < MAX_LAYERS; ++l) {
            for (size_t k = 0; k < 4; ++k) {
                layer_keys[l][k] = deriveLayerKeyWord(l, k);
            }
        }
    }

    // ------------------------------------------------------------------------
    // Basic Info / Policies
    // ------------------------------------------------------------------------
    size_t getNumLayers() const { return num_layers; }
    size_t getNumWords()  const { return num_words; }

    void addLayers(size_t count) {
        size_t requested = num_layers + count;
        if (requested > MAX_LAYERS) requested = MAX_LAYERS;

        for (size_t l = num_layers; l < requested; ++l) {
            layer_access[l] = true;
            layer_is_encrypted[l] = false;
            layer_has_hidden_key[l] = false;
            layer_log[l][0] = '\0';
            for (size_t w = 0; w < num_words; ++w) {
                memory[l][w] = 0u;
            }
        }

        num_layers = requested;
        appendLog(layer_log[DEFAULT_LAYER], "[LAYERS UPDATED] ");
    }

    bool isLayerEncrypted(size_t layer) const {
        if (!isValidLayer(layer)) return false;
        return layer_is_encrypted[layer];
    }

    size_t pickRandomLayer() const {
        lfsr_state ^= lfsr_state << 13;
        lfsr_state ^= lfsr_state >> 17;
        lfsr_state ^= lfsr_state << 5;
        if (num_layers == 0) return DEFAULT_LAYER;
        return (size_t)(lfsr_state % (uint32_t)num_layers);
    }

    void setLayerAccess(size_t layer, bool allowed) {
        if (!isValidLayer(layer)) return;
        layer_access[layer] = allowed;
    }

    const char* getKeyLayerStatus(size_t layer) const {
        if (!isValidLayer(layer)) return "Invalid layer.";
        return layer_log[layer];
    }

    void print() const {
        for (size_t l = 0; l < num_layers; ++l) {
            std::cout << "Layer " << l << ": ";
            for (size_t w = 0; w < num_words; ++w) {
                std::cout << std::hex << memory[l][w] << " ";
            }
            std::cout << "| Log: " << layer_log[l] << std::endl;
        }
    }

    // ------------------------------------------------------------------------
    // Read / Write Paths
    // ------------------------------------------------------------------------
    uint32_t rawRead(size_t layer, size_t addr) const {
        if (!isValidLayer(layer)) return 0u;
        if (addr >= num_words) return 0u;
        return memory[layer][addr];
    }

    uint32_t read(size_t layer, size_t addr) {
        if (!isValidLayer(layer)) return 0xFFFFFFFFu;
        if (addr >= num_words) return 0xDEADBEEFu;
        if (!layer_access[layer]) return 0xFFFFFFFFu;

        if (!layer_is_encrypted[layer]) {
            return memory[layer][addr];
        }

        size_t base = (addr / INSTRS_PER_BLOCK) * INSTRS_PER_BLOCK;
        if ((base + INSTRS_PER_BLOCK) > num_words) {
            return 0xDEADBEEFu;
        }

        uint32_t in[INSTRS_PER_BLOCK] = {
            memory[layer][base + 0],
            memory[layer][base + 1],
            memory[layer][base + 2],
            memory[layer][base + 3]
        };

        uint32_t out[INSTRS_PER_BLOCK];
        aes_decrypt_block(in, layer_keys[layer], out);

        const uint32_t scramble_key = 0xCAFEBABEu ^ (uint32_t)(layer * 0x9E3779B9u);
        return out[addr % INSTRS_PER_BLOCK] ^ scramble_key;
    }

    void write(size_t layer, size_t addr, uint32_t value) {
        if (!isValidLayer(layer)) return;
        if (addr >= num_words || !layer_access[layer]) return;

        if (!layer_is_encrypted[layer]) {
            memory[layer][addr] = value;

            char tmp[24];
            snprintf(tmp, sizeof(tmp), "W%u(%u) ", (unsigned)layer, (unsigned)addr);
            appendLog(layer_log[layer], tmp);
            return;
        }

        size_t base = (addr / INSTRS_PER_BLOCK) * INSTRS_PER_BLOCK;
        if ((base + INSTRS_PER_BLOCK) > num_words) return;

        uint32_t in[INSTRS_PER_BLOCK] = {
            memory[layer][base + 0],
            memory[layer][base + 1],
            memory[layer][base + 2],
            memory[layer][base + 3]
        };

        uint32_t plain[INSTRS_PER_BLOCK];
        aes_decrypt_block(in, layer_keys[layer], plain);

        const uint32_t scramble_key = 0xCAFEBABEu ^ (uint32_t)(layer * 0x9E3779B9u);
        for (int i = 0; i < INSTRS_PER_BLOCK; ++i) {
            plain[i] ^= scramble_key;
        }
        plain[addr % INSTRS_PER_BLOCK] = value;
        for (int i = 0; i < INSTRS_PER_BLOCK; ++i) {
            plain[i] ^= scramble_key;
        }

        uint32_t enc[INSTRS_PER_BLOCK];
        aes_encrypt_block(plain, layer_keys[layer], enc);

        for (int i = 0; i < INSTRS_PER_BLOCK; ++i) {
            memory[layer][base + (size_t)i] = enc[i];
        }

        char tmp[24];
        snprintf(tmp, sizeof(tmp), "W%u(%u) ", (unsigned)layer, (unsigned)addr);
        appendLog(layer_log[layer], tmp);
    }

    // ------------------------------------------------------------------------
    // Scrambling / Encryption
    // ------------------------------------------------------------------------
    void scrambleLayerWithKey(size_t layer, uint32_t key) {
        if (!isValidLayer(layer)) return;
        if (layer_is_encrypted[layer]) return;

        for (size_t i = 0; i < num_words; ++i) {
            memory[layer][i] ^= key;
        }

        appendLog(layer_log[layer], "[SCRAMBLED] ");
        invalidateCaches();
    }

    void unscrambleLayerWithKey(size_t layer, uint32_t key) {
        if (!isValidLayer(layer)) return;

        for (size_t i = 0; i < num_words; ++i) {
            memory[layer][i] ^= key;
        }

        appendLog(layer_log[layer], "[UNSCRAMBLED] ");
        invalidateCaches();
    }

    void scrambleLayer(size_t layer) {
        if (!isValidLayer(layer)) return;
        if (layer_is_encrypted[layer]) return;

        uint32_t x = 0x9E3779B9u ^ (uint32_t)(layer * 0x85EBCA6Bu);
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;

        for (size_t i = 0; i < num_words; ++i) {
            memory[layer][i] ^= x;
        }

        appendLog(layer_log[layer], "[SCRAMBLED] ");
        invalidateCaches();
    }

    void encryptLayer(size_t layer) {
        if (!isValidLayer(layer)) return;
        if (layer_is_encrypted[layer]) return;

        const uint32_t scramble_key = 0xCAFEBABEu ^ (uint32_t)(layer * 0x9E3779B9u);
        scrambleLayerWithKey(layer, scramble_key);

        for (size_t w = 0; w + INSTRS_PER_BLOCK <= num_words; w += INSTRS_PER_BLOCK) {
            uint32_t out[INSTRS_PER_BLOCK];
            aes_encrypt_block(&memory[layer][w], layer_keys[layer], out);
            for (int i = 0; i < INSTRS_PER_BLOCK; ++i) {
                memory[layer][w + (size_t)i] = out[i];
            }
        }

        layer_is_encrypted[layer] = true;
        appendLog(layer_log[layer], "[AES ENCRYPTED] ");
        invalidateCaches();
    }

    void decryptLayer(size_t layer) {
        if (!isValidLayer(layer)) return;
        if (!layer_is_encrypted[layer]) return;

        for (size_t w = 0; w + INSTRS_PER_BLOCK <= num_words; w += INSTRS_PER_BLOCK) {
            uint32_t out[INSTRS_PER_BLOCK];
            aes_decrypt_block(&memory[layer][w], layer_keys[layer], out);
            for (int i = 0; i < INSTRS_PER_BLOCK; ++i) {
                memory[layer][w + (size_t)i] = out[i];
            }
        }

        appendLog(layer_log[layer], "[AES DECRYPTED] ");

        const uint32_t scramble_key = 0xCAFEBABEu ^ (uint32_t)(layer * 0x9E3779B9u);
        unscrambleLayerWithKey(layer, scramble_key);

        layer_is_encrypted[layer] = false;
        invalidateCaches();
    }

    // ------------------------------------------------------------------------
    // Hardware Obfuscation / Root Derivation
    // ------------------------------------------------------------------------
    void setHardwareKey(uint32_t new_key) {
        hardware_key = new_key;
        initLayerKeys();
        appendLog(layer_log[DEFAULT_LAYER], "[HW KEY UPDATED] ");
    }

    uint32_t deriveHardwareWord(uint32_t nonce, uint32_t salt) const {
        uint32_t x = hardware_key ^ nonce ^ (salt * 0x9E3779B9u);
        return mix32(x) ^ 0xA5C39D27u;
    }

    void hardwareObfuscate() {
        for (size_t l = 0; l < num_layers; ++l) {
            if (layer_is_encrypted[l]) continue;
            if (layer_has_hidden_key[l]) continue;

            uint32_t key = hardware_key ^ (uint32_t)(0x9E3779B9u * (uint32_t)(l + 1u));
            for (size_t w = 0; w < num_words; ++w) {
                memory[l][w] ^= key;
            }

            appendLog(layer_log[l], "[HW OBFUSCATED] ");
        }

        invalidateCaches();
    }

    // ------------------------------------------------------------------------
    // Anti-Tamper
    // ------------------------------------------------------------------------
    struct TamperPoint {
        size_t layer;
        size_t addr;
        uint32_t expected;
    };

    void checkMultipleTamper(const TamperPoint* points, size_t num_points) {
        if (points == nullptr) return;

        for (size_t i = 0; i < num_points; ++i) {
            checkTamper(points[i].layer, points[i].addr, points[i].expected);
        }
    }

    void checkTamper(size_t layer, size_t addr, uint32_t expected) {
        if (!isValidLayer(layer)) return;
        if (addr >= num_words) return;

        uint32_t observed = logicalReadNoAccessCheck(layer, addr);
        if (observed != expected) {
            tamper_detected = true;
            tamper_events++;
            security_lockdown = true;

            char tmp[48];
            snprintf(tmp, sizeof(tmp), "[TAMPER L%u @%u] ",
                     (unsigned)layer, (unsigned)addr);
            appendLog(layer_log[layer], tmp);
            autoReset();
        }
    }

    void autoReset() {
        for (size_t l = 0; l < num_layers; ++l) {
            for (size_t w = 0; w < num_words; ++w) {
                memory[l][w] = 0u;
            }

            layer_is_encrypted[l] = false;
            layer_has_hidden_key[l] = false;
            appendLog(layer_log[l], "[AUTO RESET] ");
        }

        security_lockdown = true;
        invalidateCaches();
    }

    void autoResetCritical(const size_t critical_layers[], size_t num_critical) {
        if (critical_layers == nullptr) return;

        for (size_t i = 0; i < num_critical; ++i) {
            size_t l = critical_layers[i];
            if (!isValidLayer(l)) continue;

            for (size_t w = 0; w < num_words; ++w) {
                memory[l][w] = 0u;
            }

            layer_is_encrypted[l] = false;
            layer_has_hidden_key[l] = false;
            tamper_events++;
            security_lockdown = true;
            appendLog(layer_log[l], "[CRITICAL AUTO RESET] ");
        }

        invalidateCaches();
    }

    void lockSecurity(const char* reason) {
        tamper_detected = true;
        tamper_events++;
        security_lockdown = true;

        if (reason && reason[0] != '\0') {
            char tmp[64];
            snprintf(tmp, sizeof(tmp), "[LOCK: %s] ", reason);
            appendLog(layer_log[DEFAULT_LAYER], tmp);
        } else {
            appendLog(layer_log[DEFAULT_LAYER], "[LOCK] ");
        }
    }

    void clearSecurityLockdown() {
        security_lockdown = false;
        tamper_detected = false;
        appendLog(layer_log[DEFAULT_LAYER], "[LOCK CLEARED] ");
    }

    bool isSecurityLocked() const {
        return security_lockdown;
    }

    uint32_t getTamperCount() const {
        return tamper_events;
    }

    const char* getTamperStatus() const {
        return tamper_detected ? "Tamper detected! Memory reset." : "No tamper detected.";
    }

    // ------------------------------------------------------------------------
    // Key Hiding / Extraction
    // ------------------------------------------------------------------------
    void hideKeyInLayer(size_t layer,
                        const uint32_t key[],
                        size_t key_words,
                        const size_t secret[],
                        size_t secret_len) {
        if (!isValidLayer(layer)) return;
        if (key == nullptr || secret == nullptr) return;
        if (secret_len % 32 != 0) return;
        if (key_words == 0 || key_words * 32 != secret_len) return;
        if (layer_is_encrypted[layer]) return;

        for (size_t i = 0; i < secret_len; ++i) {
            size_t bit_pos = secret[i];
            size_t word_index = bit_pos / 32;
            size_t bit_in_word = bit_pos % 32;
            if (word_index >= num_words) continue;

            size_t key_word = i / 32;
            size_t key_bit = i % 32;
            if (key_word >= key_words) return;

            uint32_t bit_val = (key[key_word] >> key_bit) & 1u;
            memory[layer][word_index] &= ~(1u << bit_in_word);
            memory[layer][word_index] |= (bit_val << bit_in_word);
        }

        appendLog(layer_log[layer], "[KEY HIDDEN] ");
        layer_has_hidden_key[layer] = true;
    }

    // Backward-compatible wrapper.
    void hideKeyInLayer(size_t layer, const uint32_t key[], const size_t secret[], size_t secret_len) {
        hideKeyInLayer(layer, key, secret_len / 32, secret, secret_len);
    }

    void extractKeyFromLayer(size_t layer,
                             const size_t secret[],
                             size_t secret_len,
                             uint32_t key[],
                             size_t key_words) {
        if (key == nullptr) return;
        for (size_t k = 0; k < key_words; ++k) key[k] = 0u;

        if (!isValidLayer(layer)) return;
        if (secret == nullptr) return;

        bool prev_flag = disable_processing_scramble;
        if (processing_layer == layer) {
            disable_processing_scramble = true;
        }

        if (key_words == 0 || key_words * 32 != secret_len) {
            disable_processing_scramble = prev_flag;
            return;
        }

        if (layer_is_encrypted[layer]) {
            disable_processing_scramble = prev_flag;
            return;
        }

        for (size_t i = 0; i < secret_len; ++i) {
            size_t bit_pos = secret[i];
            size_t word_index = bit_pos / 32;
            size_t bit_in_word = bit_pos % 32;
            if (word_index >= num_words) continue;

            size_t key_word = i / 32;
            size_t key_bit = i % 32;
            if (key_word >= key_words) {
                disable_processing_scramble = prev_flag;
                return;
            }

            uint32_t bit_val = (memory[layer][word_index] >> bit_in_word) & 1u;
            key[key_word] |= (bit_val << key_bit);
        }

        appendLog(layer_log[layer], "[KEY EXTRACTED] ");
        disable_processing_scramble = prev_flag;
    }

    // ------------------------------------------------------------------------
    // Processing Layer (non-destructive)
    // ------------------------------------------------------------------------
    void scrambleProcessingLayer(uint32_t custom_key = 0) {
        if (disable_processing_scramble) return;
        if (processing_layer == SIZE_MAX) return;
        if (!isValidLayer(processing_layer)) return;

        uint32_t key = custom_key ? custom_key : (0xA5A5A5A5u ^ (uint32_t)processing_layer);
        char tmp[48];
        snprintf(tmp, sizeof(tmp), "[VIRTUAL SCRAMBLE L%u 0x%08X] ",
                 (unsigned)processing_layer, (unsigned)key);
        appendLog(layer_log[processing_layer], tmp);
    }

    void logReverseEngAttempt(const char* type, size_t addr) {
        if (processing_layer != SIZE_MAX && isValidLayer(processing_layer)) {
            char tmp[72];
            snprintf(tmp, sizeof(tmp), "[REVERSE ENG ATTEMPT: %s L%u @%u] ",
                     type ? type : "UNKNOWN",
                     (unsigned)processing_layer,
                     (unsigned)addr);
            appendLog(layer_log[processing_layer], tmp);
        }
    }

    uint32_t protectedRead(size_t layer, size_t addr) {
        if (!isValidLayer(layer)) return 0xFFFFFFFFu;

        if (layer == processing_layer && !disable_processing_scramble) {
            scrambleProcessingLayer();
            logReverseEngAttempt("READ", addr);
        }

        return read(layer, addr);
    }

    void protectedWrite(size_t layer, size_t addr, uint32_t value) {
        if (!isValidLayer(layer)) return;

        if (layer == processing_layer && !disable_processing_scramble) {
            scrambleProcessingLayer();
            logReverseEngAttempt("WRITE", addr);
        }

        write(layer, addr, value);
    }

    void enableProcessingLayer(size_t layer) {
        if (!isValidLayer(layer)) return;

        processing_layer = layer;
        char tmp[48];
        snprintf(tmp, sizeof(tmp), "[PROCESSING LAYER %u ENABLED] ", (unsigned)layer);
        appendLog(layer_log[layer], tmp);
    }

    void clearProcessingLayer() {
        if (processing_layer != SIZE_MAX && isValidLayer(processing_layer)) {
            appendLog(layer_log[processing_layer], "[PROCESSING CLEARED] ");
        }
        processing_layer = SIZE_MAX;
    }

    uint32_t readProcessing(size_t addr) {
        if (processing_layer == SIZE_MAX) return 0xDEADBEEFu;
        if (!isValidLayer(processing_layer)) return 0xFFFFFFFFu;

        if (!disable_processing_scramble) {
            scrambleProcessingLayer();
            appendLog(layer_log[processing_layer], "[REVERSE ENG DETECTED] ");
        }

        return read(processing_layer, addr);
    }

    bool isProcessingLayerEnabled() const {
        return processing_layer != SIZE_MAX && isValidLayer(processing_layer);
    }

    const char* getProcessingLayerStatus() const {
        if (processing_layer == SIZE_MAX) return "No processing layer enabled.";
        if (!isValidLayer(processing_layer)) return "Invalid processing layer.";
        return layer_log[processing_layer];
    }

    // ------------------------------------------------------------------------
    // Batch Operations
    // ------------------------------------------------------------------------
    void clearLayer(size_t layer) {
        if (!isValidLayer(layer)) return;

        for (size_t w = 0; w < num_words; ++w) {
            memory[layer][w] = 0u;
        }

        layer_is_encrypted[layer] = false;
        layer_has_hidden_key[layer] = false;
        appendLog(layer_log[layer], "[CLEARED] ");
        invalidateCaches();
    }

    void copyLayer(size_t src, size_t dst) {
        if (!isValidLayer(src) || !isValidLayer(dst)) return;

        for (size_t w = 0; w < num_words; ++w) {
            memory[dst][w] = memory[src][w];
        }

        for (int k = 0; k < 4; ++k) {
            layer_keys[dst][k] = layer_keys[src][k];
        }

        layer_is_encrypted[dst] = layer_is_encrypted[src];
        layer_has_hidden_key[dst] = layer_has_hidden_key[src];
        layer_access[dst] = layer_access[src];

        char tmp[48];
        snprintf(tmp, sizeof(tmp), "[COPIED from L%u] ", (unsigned)src);
        appendLog(layer_log[dst], tmp);
        invalidateCaches();
    }
};

// ------------------------------------------------------------------------
// Global externs
// ------------------------------------------------------------------------
extern StackedMemory3D stackedMemory;
extern uint32_t reg_file[NUM_REGS];
extern int secret_map[128];

// ------------------------------------------------------------------------
// Top function for HLS
// ------------------------------------------------------------------------
extern "C" void Crypto3DStackCPU_top(volatile uint32_t* image,
                                      uint32_t word_count,
                                      volatile uint32_t* status_word);

#endif // CRYPTO3DSTACKCPU_H
