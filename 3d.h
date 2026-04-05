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
#define MAX_LAYERS   1
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
// StackedMemory3D Abstraction (Single-Layer Policy)
// ------------------------------------------------------------------------
class StackedMemory3D {
public:
    static constexpr size_t ACTIVE_LAYER = 0;

private:
    mutable uint32_t lfsr_state = 0xACE1u;
    bool layer_is_encrypted[MAX_LAYERS] = {false};
    bool layer_has_hidden_key[MAX_LAYERS] = {false};
    bool disable_processing_scramble = false;
    bool tamper_detected = false;
    bool security_lockdown = false;
    uint32_t tamper_events = 0;
    size_t processing_layer = SIZE_MAX;
    uint32_t hardware_key = 0xA1B2C3D4;

    size_t normalizeLayer(size_t /*layer*/) const {
        return ACTIVE_LAYER;
    }

    uint32_t logicalReadNoAccessCheck(size_t addr) const {
        if (addr >= num_words) return 0xDEADBEEF;
        if (!layer_is_encrypted[ACTIVE_LAYER]) {
            return memory[ACTIVE_LAYER][addr];
        }

        size_t base = (addr / 4) * 4;
        uint32_t in[4] = {
            memory[ACTIVE_LAYER][base + 0],
            memory[ACTIVE_LAYER][base + 1],
            memory[ACTIVE_LAYER][base + 2],
            memory[ACTIVE_LAYER][base + 3]
        };
        uint32_t key_local[4] = {
            layer_keys[ACTIVE_LAYER][0],
            layer_keys[ACTIVE_LAYER][1],
            layer_keys[ACTIVE_LAYER][2],
            layer_keys[ACTIVE_LAYER][3]
        };
        uint32_t out[4];
        aes_decrypt_block(in, key_local, out);
        return out[addr % 4];
    }

    static uint32_t mix32(uint32_t x) {
        x ^= x >> 16;
        x *= 0x7FEB352Du;
        x ^= x >> 15;
        x *= 0x846CA68Bu;
        x ^= x >> 16;
        return x;
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
        size_t len = 0;
        while (len < MAX_LOG_LEN && dst[len] != '\0') {
            len++;
        }

        for (size_t i = 0; tag[i] != '\0' && (len + i) < (MAX_LOG_LEN - 1); i++) {
            dst[len + i] = tag[i];
        }

        dst[MAX_LOG_LEN - 1] = '\0';
    }

    StackedMemory3D(size_t layers, size_t words_per_layer)
        : num_layers(1)
    {
        (void)layers;

        num_words = (words_per_layer > MAX_WORDS ? MAX_WORDS : words_per_layer);
        num_words = (num_words / 4) * 4;

        for (size_t w = 0; w < num_words; ++w) memory[ACTIVE_LAYER][w] = 0;
        layer_access[ACTIVE_LAYER] = true;
        layer_log[ACTIVE_LAYER][0] = '\0';
        layer_is_encrypted[ACTIVE_LAYER] = false;
        layer_has_hidden_key[ACTIVE_LAYER] = false;

        initLayerKeys();
    }

    void initLayerKeys() {
        layer_keys[ACTIVE_LAYER][0] = 0xA1B2C3D4;
        layer_keys[ACTIVE_LAYER][1] = 0xB2C3D4E5;
        layer_keys[ACTIVE_LAYER][2] = 0xC3D4E5F6;
        layer_keys[ACTIVE_LAYER][3] = 0xD4E5F607;
    }

    // ------------------------------------------------------------------------
    // Basic Info / Policies
    // ------------------------------------------------------------------------
    size_t getNumLayers() const { return 1; }
    size_t getNumWords()  const { return num_words; }

    void addLayers(size_t /*count*/) {
        // Single-layer policy: fixed to one layer.
        num_layers = 1;
    }

    bool isLayerEncrypted(size_t l) const {
        (void)l;
        return layer_is_encrypted[ACTIVE_LAYER];
    }

    size_t pickRandomLayer() const {
        (void)lfsr_state;
        return ACTIVE_LAYER;
    }

    void setLayerAccess(size_t layer, bool allowed) {
        size_t nl = normalizeLayer(layer);
        layer_access[nl] = allowed;
    }

    const char* getKeyLayerStatus(size_t layer) const {
        (void)layer;
        return layer_log[ACTIVE_LAYER];
    }

    void print() const {
        std::cout << "Layer 0: ";
        for (size_t w = 0; w < num_words; ++w) {
            std::cout << std::hex << memory[ACTIVE_LAYER][w] << " ";
        }
        std::cout << "| Log: " << layer_log[ACTIVE_LAYER] << std::endl;
    }

    // ------------------------------------------------------------------------
    // Read / Write Paths
    // ------------------------------------------------------------------------
    uint32_t rawRead(size_t layer, size_t addr) const {
        (void)layer;
        if (addr >= num_words) return 0;
        return memory[ACTIVE_LAYER][addr];
    }

    uint32_t read(size_t layer, size_t addr) {
        size_t nl = normalizeLayer(layer);
        if (addr >= num_words) return 0xDEADBEEF;
        if (!layer_access[nl]) return 0xFFFFFFFF;

        if (!layer_is_encrypted[nl]) {
            return memory[nl][addr];
        }

        size_t base = (addr / 4) * 4;
        uint32_t in[4] = {
            memory[nl][base + 0],
            memory[nl][base + 1],
            memory[nl][base + 2],
            memory[nl][base + 3]
        };
        uint32_t out[4];
        aes_decrypt_block(in, layer_keys[nl], out);
        return out[addr % 4];
    }

    void write(size_t layer, size_t addr, uint32_t value) {
        size_t nl = normalizeLayer(layer);
        if (addr >= num_words || !layer_access[nl]) return;

        if (!layer_is_encrypted[nl]) {
            memory[nl][addr] = value;
            char tmp[16];
            snprintf(tmp, sizeof(tmp), "W(%u) ", (unsigned)addr);
            appendLog(layer_log[nl], tmp);
            return;
        }

        size_t base = (addr / 4) * 4;
        uint32_t in[4] = {
            memory[nl][base + 0],
            memory[nl][base + 1],
            memory[nl][base + 2],
            memory[nl][base + 3]
        };
        uint32_t plain[4];
        aes_decrypt_block(in, layer_keys[nl], plain);
        plain[addr % 4] = value;

        uint32_t enc[4];
        aes_encrypt_block(plain, layer_keys[nl], enc);
        for (int i = 0; i < 4; ++i) memory[nl][base + i] = enc[i];

        char tmp[16];
        snprintf(tmp, sizeof(tmp), "W(%u) ", (unsigned)addr);
        appendLog(layer_log[nl], tmp);
    }

    // ------------------------------------------------------------------------
    // Scrambling / Encryption
    // ------------------------------------------------------------------------
    void scrambleLayerWithKey(size_t layer, uint32_t key) {
        size_t nl = normalizeLayer(layer);
        if (layer_is_encrypted[nl]) return;

        for (size_t i = 0; i < num_words; ++i) {
            memory[nl][i] ^= key;
        }
        appendLog(layer_log[nl], "[SCRAMBLED] ");
    }

    void unscrambleLayerWithKey(size_t layer, uint32_t key) {
        size_t nl = normalizeLayer(layer);
        for (size_t i = 0; i < num_words; ++i) {
            memory[nl][i] ^= key;
        }
        appendLog(layer_log[nl], "[UNSCRAMBLED] ");
    }

    void scrambleLayer(size_t layer) {
        size_t nl = normalizeLayer(layer);
        if (layer_is_encrypted[nl]) return;

        uint32_t x = 0x9E3779B9u;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;

        for (size_t i = 0; i < num_words; ++i) memory[nl][i] ^= x;
        appendLog(layer_log[nl], "[SCRAMBLED] ");
    }

    void encryptLayer(size_t layer) {
        size_t nl = normalizeLayer(layer);
        if (layer_is_encrypted[nl]) return;

        const uint32_t scramble_key = 0xCAFEBABE;
        scrambleLayerWithKey(nl, scramble_key);

        for (size_t w = 0; w + 4 <= num_words; w += 4) {
            uint32_t out[4];
            aes_encrypt_block(&memory[nl][w], layer_keys[nl], out);
            for (int i = 0; i < 4; ++i) memory[nl][w + i] = out[i];
        }

        layer_is_encrypted[nl] = true;
        appendLog(layer_log[nl], "[AES ENCRYPTED] ");
        invalidateCaches();
    }

    void decryptLayer(size_t layer) {
        size_t nl = normalizeLayer(layer);
        if (!layer_is_encrypted[nl]) return;

        for (size_t w = 0; w + 4 <= num_words; w += 4) {
            uint32_t out[4];
            aes_decrypt_block(&memory[nl][w], layer_keys[nl], out);
            for (int i = 0; i < 4; ++i) memory[nl][w + i] = out[i];
        }

        appendLog(layer_log[nl], "[AES DECRYPTED] ");
        const uint32_t scramble_key = 0xCAFEBABE;
        unscrambleLayerWithKey(nl, scramble_key);
        layer_is_encrypted[nl] = false;
        invalidateCaches();
    }

    // ------------------------------------------------------------------------
    // Hardware Obfuscation
    // ------------------------------------------------------------------------
    void setHardwareKey(uint32_t new_key) {
        hardware_key = new_key;
        appendLog(layer_log[ACTIVE_LAYER], "[HW KEY UPDATED] ");
    }

    uint32_t deriveHardwareWord(uint32_t nonce, uint32_t salt) const {
        uint32_t x = hardware_key ^ nonce ^ (salt * 0x9E3779B9u);
        return mix32(x) ^ 0xA5C39D27u;
    }

    void hardwareObfuscate() {
        if (layer_is_encrypted[ACTIVE_LAYER]) return;
        if (layer_has_hidden_key[ACTIVE_LAYER]) return;

        for (size_t w = 0; w < num_words; ++w) {
            memory[ACTIVE_LAYER][w] ^= hardware_key;
        }
        appendLog(layer_log[ACTIVE_LAYER], "[HW OBFUSCATED] ");
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
        for (size_t i = 0; i < num_points; ++i) {
            checkTamper(points[i].layer, points[i].addr, points[i].expected);
        }
    }

    void checkTamper(size_t layer, size_t addr, uint32_t expected) {
        (void)layer;
        if (addr >= num_words) return;

        uint32_t observed = logicalReadNoAccessCheck(addr);
        if (observed != expected) {
            tamper_detected = true;
            tamper_events++;
            security_lockdown = true;
            char tmp[32];
            snprintf(tmp, sizeof(tmp), "[TAMPER DETECTED @%u] ", (unsigned)addr);
            appendLog(layer_log[ACTIVE_LAYER], tmp);
            autoReset();
        }
    }

    void autoReset() {
        for (size_t w = 0; w < num_words; ++w) memory[ACTIVE_LAYER][w] = 0;
        layer_is_encrypted[ACTIVE_LAYER] = false;
        layer_has_hidden_key[ACTIVE_LAYER] = false;
        security_lockdown = true;
        appendLog(layer_log[ACTIVE_LAYER], "[AUTO RESET] ");
        invalidateCaches();
    }

    void autoResetCritical(const size_t critical_layers[], size_t num_critical) {
        for (size_t i = 0; i < num_critical; ++i) {
            if (normalizeLayer(critical_layers[i]) != ACTIVE_LAYER) continue;
            for (size_t w = 0; w < num_words; ++w) memory[ACTIVE_LAYER][w] = 0;
            layer_is_encrypted[ACTIVE_LAYER] = false;
            layer_has_hidden_key[ACTIVE_LAYER] = false;
            tamper_events++;
            security_lockdown = true;
            appendLog(layer_log[ACTIVE_LAYER], "[CRITICAL AUTO RESET] ");
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
            appendLog(layer_log[ACTIVE_LAYER], tmp);
        } else {
            appendLog(layer_log[ACTIVE_LAYER], "[LOCK] ");
        }
    }

    void clearSecurityLockdown() {
        security_lockdown = false;
        tamper_detected = false;
        appendLog(layer_log[ACTIVE_LAYER], "[LOCK CLEARED] ");
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
    void hideKeyInLayer(size_t layer, const uint32_t key[], size_t key_words, const size_t secret[], size_t secret_len) {
        size_t nl = normalizeLayer(layer);
        if (secret_len % 32 != 0) return;
        if (key_words == 0 || key_words * 32 != secret_len) return;
        if (layer_is_encrypted[nl]) return;

        for (size_t i = 0; i < secret_len; ++i) {
            size_t bit_pos = secret[i];
            size_t word_index = bit_pos / 32;
            size_t bit_in_word = bit_pos % 32;
            if (word_index >= num_words) continue;

            size_t key_word = i / 32;
            size_t key_bit = i % 32;
            if (key_word >= key_words) return;

            uint32_t bit_val = (key[key_word] >> key_bit) & 1;
            memory[nl][word_index] &= ~(1u << bit_in_word);
            memory[nl][word_index] |= (bit_val << bit_in_word);
        }

        appendLog(layer_log[nl], "[KEY HIDDEN] ");
        layer_has_hidden_key[nl] = true;
    }

    // Backward-compatible wrapper.
    void hideKeyInLayer(size_t layer, const uint32_t key[], const size_t secret[], size_t secret_len) {
        hideKeyInLayer(layer, key, secret_len / 32, secret, secret_len);
    }

    void extractKeyFromLayer(size_t layer, const size_t secret[], size_t secret_len, uint32_t key[], size_t key_words) {
        size_t nl = normalizeLayer(layer);

        bool prev_flag = disable_processing_scramble;
        if (processing_layer == ACTIVE_LAYER) {
            disable_processing_scramble = true;
        }

        for (size_t k = 0; k < key_words; ++k) key[k] = 0;

        if (key_words == 0 || key_words * 32 != secret_len) {
            disable_processing_scramble = prev_flag;
            return;
        }
        if (layer_is_encrypted[nl]) {
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

            uint32_t bit_val = (memory[nl][word_index] >> bit_in_word) & 1;
            key[key_word] |= (bit_val << key_bit);
        }

        appendLog(layer_log[nl], "[KEY EXTRACTED] ");
        disable_processing_scramble = prev_flag;
    }

    // ------------------------------------------------------------------------
    // Processing Layer (non-destructive)
    // ------------------------------------------------------------------------
    void scrambleProcessingLayer(uint32_t custom_key = 0) {
        if (disable_processing_scramble) return;
        if (processing_layer == SIZE_MAX) return;

        uint32_t key = custom_key ? custom_key : 0xA5A5A5A5u;
        char tmp[40];
        snprintf(tmp, sizeof(tmp), "[VIRTUAL SCRAMBLE 0x%08X] ", (unsigned)key);
        appendLog(layer_log[processing_layer], tmp);
    }

    void logReverseEngAttempt(const char* type, size_t addr) {
        if (processing_layer != SIZE_MAX) {
            char tmp[64];
            snprintf(tmp, sizeof(tmp), "[REVERSE ENG ATTEMPT: %s @%u] ", type, (unsigned)addr);
            appendLog(layer_log[processing_layer], tmp);
        }
    }

    uint32_t protectedRead(size_t layer, size_t addr) {
        size_t nl = normalizeLayer(layer);
        if (nl == processing_layer && !disable_processing_scramble) {
            scrambleProcessingLayer();
            logReverseEngAttempt("READ", addr);
        }
        return read(nl, addr);
    }

    void protectedWrite(size_t layer, size_t addr, uint32_t value) {
        size_t nl = normalizeLayer(layer);
        if (nl == processing_layer && !disable_processing_scramble) {
            scrambleProcessingLayer();
            logReverseEngAttempt("WRITE", addr);
        }
        write(nl, addr, value);
    }

    void enableProcessingLayer(size_t layer) {
        (void)layer;
        processing_layer = ACTIVE_LAYER;
        appendLog(layer_log[ACTIVE_LAYER], "[PROCESSING LAYER ENABLED] ");
    }

    void clearProcessingLayer() {
        if (processing_layer != SIZE_MAX) {
            appendLog(layer_log[processing_layer], "[PROCESSING CLEARED] ");
            processing_layer = SIZE_MAX;
        }
    }

    uint32_t readProcessing(size_t addr) {
        if (processing_layer == SIZE_MAX) return 0xDEADBEEF;
        if (!disable_processing_scramble) {
            scrambleProcessingLayer();
            appendLog(layer_log[processing_layer], "[REVERSE ENG DETECTED] ");
        }
        return read(processing_layer, addr);
    }

    bool isProcessingLayerEnabled() const {
        return processing_layer != SIZE_MAX;
    }

    const char* getProcessingLayerStatus() const {
        if (processing_layer == SIZE_MAX) return "No processing layer enabled.";
        return layer_log[processing_layer];
    }

    // ------------------------------------------------------------------------
    // Batch Operations
    // ------------------------------------------------------------------------
    void clearLayer(size_t layer) {
        size_t nl = normalizeLayer(layer);
        for (size_t w = 0; w < num_words; ++w) memory[nl][w] = 0;
        layer_is_encrypted[nl] = false;
        layer_has_hidden_key[nl] = false;
        appendLog(layer_log[nl], "[CLEARED] ");
        invalidateCaches();
    }

    void copyLayer(size_t src, size_t dst) {
        size_t s = normalizeLayer(src);
        size_t d = normalizeLayer(dst);

        for (size_t w = 0; w < num_words; ++w) memory[d][w] = memory[s][w];
        layer_is_encrypted[d] = layer_is_encrypted[s];
        layer_has_hidden_key[d] = layer_has_hidden_key[s];

        char tmp[40];
        snprintf(tmp, sizeof(tmp), "[COPIED from %u] ", (unsigned)src);
        appendLog(layer_log[d], tmp);
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
