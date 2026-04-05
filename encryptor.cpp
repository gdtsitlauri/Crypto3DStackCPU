#include <iostream>
#include <iomanip>
#include <cstdint>
#include "3d.h"
#include "header.h"
#include <fstream>
#include <cstdlib>
#include <random>
#include <chrono>

extern StackedMemory3D stackedMemory;

static inline uint32_t local_mix32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 15;
    x *= 0x846CA68Bu;
    x ^= x >> 16;
    return x;
}

static uint32_t key_fingerprint(const uint32_t key[4]) {
    uint32_t fp = 0x6D5A56A9u;
    for (int i = 0; i < 4; ++i) {
        fp = local_mix32(fp ^ key[i] ^ (0x9E3779B9u * (uint32_t)(i + 1)));
    }
    return fp;
}

static void generate_random_app_key(uint32_t key[4], uint32_t epoch, uint32_t text_words, uint32_t data_words) {
    uint64_t now_ticks = (uint64_t)std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::random_device rd;
    std::seed_seq seq{
        (uint32_t)rd(), (uint32_t)rd(), (uint32_t)rd(), (uint32_t)rd(),
        (uint32_t)(now_ticks & 0xFFFFFFFFu), (uint32_t)((now_ticks >> 32) & 0xFFFFFFFFu),
        epoch, text_words, data_words, 0xC4A1B2D3u
    };

    std::mt19937 gen(seq);
    std::uniform_int_distribution<uint32_t> dist(0u, 0xFFFFFFFFu);
    for (int i = 0; i < 4; ++i) {
        key[i] = dist(gen);
    }

    if ((key[0] | key[1] | key[2] | key[3]) == 0u) {
        key[0] = 0xA5A5A5A5u;
    }
}

int main(int argc, char **argv) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " text.hex data.hex demo.hex [epoch]\n";
        return 1;
    }
    std::string text_file  = argv[1];
    std::string data_file  = argv[2];
    std::string output_file = argv[3];

    const int TARGET_LAYER = 0;
    const int MEM_WORDS    = static_cast<int>(stackedMemory.getNumWords());
    static constexpr int KEY_BLOCK_WORDS = 32;
    static constexpr int WORDS_PER_BLOCK = 4;
    static constexpr int TEXT_START_ADDR = KEY_BLOCK_WORDS;
    uint32_t aes_key[4] = {0u, 0u, 0u, 0u};
    uint32_t mapping_epoch = 1u;

    if (argc >= 5) {
        char *endp = nullptr;
        unsigned long parsed = std::strtoul(argv[4], &endp, 0);
        if (endp != argv[4]) {
            mapping_epoch = (uint32_t)parsed;
        }
    }

    // 1. Reset whole layer 0 to DEADBEEF
    for (int i = 0; i < MEM_WORDS; ++i) {
        if (i < KEY_BLOCK_WORDS)
            stackedMemory.protectedWrite(TARGET_LAYER, i, 0xDEADBEEF);
        else
            stackedMemory.write(TARGET_LAYER, i, 0xDEADBEEF);
    }

    // 2. Load text.hex to layer 0 (from address 32 and above)
    std::ifstream fin(text_file);
    if (!fin) {
        std::cerr << "[ERROR] Cannot open " << text_file << "\n";
        return 1;
    }
    int loaded_text = 0;
    std::string line;
    int mem_addr = TEXT_START_ADDR;
    while (mem_addr < MEM_WORDS && std::getline(fin, line)) {
        uint32_t val = 0;
        if (!line.empty()) {
            try { val = std::stoul(line, nullptr, 16); } catch (...) { val = 0; }
        }
        if (mem_addr < KEY_BLOCK_WORDS)
            stackedMemory.protectedWrite(TARGET_LAYER, mem_addr, val);
        else
            stackedMemory.write(TARGET_LAYER, mem_addr, val);
        mem_addr++;
        loaded_text++;
    }
    fin.close();
    std::cout << "[INFO] Loaded text file: " << text_file << " (" << loaded_text << " lines)" << std::endl;

    // Align text region to full AES blocks so data starts at a clean boundary.
    int text_plain_end = TEXT_START_ADDR + loaded_text;
    int text_enc_end = text_plain_end;
    if (text_enc_end % WORDS_PER_BLOCK) {
        text_enc_end += (WORDS_PER_BLOCK - (text_enc_end % WORDS_PER_BLOCK));
    }
    if (text_enc_end > MEM_WORDS) text_enc_end = MEM_WORDS;
    for (int i = text_plain_end; i < text_enc_end; ++i) {
        stackedMemory.write(TARGET_LAYER, i, 0x00000000);
    }

    if (mapping_epoch == 0u) {
        uint32_t auto_epoch = 0x13579BDFu;
        auto_epoch ^= (uint32_t)loaded_text * 0x9E3779B9u;
        auto_epoch ^= (uint32_t)text_enc_end * 0x85EBCA6Bu;
        mapping_epoch = auto_epoch ? auto_epoch : 1u;
    }

    secure_set_image_region(TEXT_START_ADDR, (uint32_t)loaded_text, (uint32_t)text_enc_end);
    secure_set_mapping_epoch(mapping_epoch);

    // 3. Load data.hex immediately after encrypted-text region.
    mem_addr = text_enc_end;

    fin.open(data_file);
    if (!fin) {
        std::cerr << "[ERROR] Cannot open " << data_file << "\n";
        return 1;
    }
    int loaded_data = 0;
    while (mem_addr < MEM_WORDS && std::getline(fin, line)) {
        uint32_t val = 0;
        if (!line.empty()) {
            try { val = std::stoul(line, nullptr, 16); } catch (...) { val = 0; }
        }
        if (mem_addr < KEY_BLOCK_WORDS)
            stackedMemory.protectedWrite(TARGET_LAYER, mem_addr, val);
        else
            stackedMemory.write(TARGET_LAYER, mem_addr, val);
        mem_addr++;
        loaded_data++;
    }
    fin.close();
    std::cout << "[INFO] Loaded data file: " << data_file << " (" << loaded_data << " lines)" << std::endl;

    int data_start = text_enc_end;
    int data_plain_end = data_start + loaded_data;
    if (data_plain_end > MEM_WORDS) data_plain_end = MEM_WORDS;

    int data_enc_end = data_plain_end;
    if (data_enc_end % WORDS_PER_BLOCK) {
        data_enc_end += (WORDS_PER_BLOCK - (data_enc_end % WORDS_PER_BLOCK));
    }
    if (data_enc_end > MEM_WORDS) data_enc_end = MEM_WORDS;

    for (int i = data_plain_end; i < data_enc_end; ++i) {
        stackedMemory.write(TARGET_LAYER, i, 0x00000000);
    }

    secure_set_data_region((uint32_t)data_start,
                           (uint32_t)loaded_data,
                           (uint32_t)data_enc_end,
                           SEC_DATA_FLAG_ENCRYPTED);

    // Generate a fresh app key per image build.
    generate_random_app_key(aes_key, mapping_epoch, (uint32_t)loaded_text, (uint32_t)loaded_data);
    uint32_t generated_key_fp = key_fingerprint(aes_key);
    std::cout << "[INFO] Generated app key fingerprint: 0x"
              << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << generated_key_fp
              << std::dec << std::nouppercase << std::endl;

    // 4. Pad with zeros up to 1024 words.
    if (mem_addr < data_enc_end) mem_addr = data_enc_end;
    while (mem_addr < MEM_WORDS) {
        if (mem_addr < KEY_BLOCK_WORDS)
            stackedMemory.protectedWrite(TARGET_LAYER, mem_addr, 0x00000000);
        else
            stackedMemory.write(TARGET_LAYER, mem_addr, 0x00000000);
        mem_addr++;
    }

    // 5. Encrypt text region [TEXT_START_ADDR, text_enc_end)
    // and place encrypted blocks through logical->physical mapping.
    const int start_block = TEXT_START_ADDR / WORDS_PER_BLOCK;
    const int end_block   = text_enc_end    / WORDS_PER_BLOCK;
    uint32_t enc_buffer[MEM_SIZE];
    for (int i = 0; i < MEM_WORDS; ++i) {
        enc_buffer[i] = stackedMemory.read(TARGET_LAYER, i);
    }

    for (int blk = start_block; blk < end_block; ++blk) {
        const int logical_addr = blk * WORDS_PER_BLOCK;
        if (logical_addr < KEY_BLOCK_WORDS) continue;

        uint32_t plain[WORDS_PER_BLOCK];
        for (int i = 0; i < WORDS_PER_BLOCK; ++i) plain[i] = stackedMemory.read(TARGET_LAYER, logical_addr + i);

        uint32_t cipher[WORDS_PER_BLOCK];
        aes_encrypt_block(plain, aes_key, cipher);

        uint32_t phys_block = secure_map_text_block((uint32_t)blk);
        int phys_addr = (int)phys_block * WORDS_PER_BLOCK;
        if (phys_addr < KEY_BLOCK_WORDS || (phys_addr + WORDS_PER_BLOCK) > MEM_WORDS) {
            std::cerr << "[ERROR] Invalid mapped text block address." << std::endl;
            return 4;
        }

        for (int i = 0; i < WORDS_PER_BLOCK; ++i) {
            enc_buffer[phys_addr + i] = cipher[i];
        }
    }

    for (int i = TEXT_START_ADDR; i < text_enc_end; ++i) {
        stackedMemory.write(TARGET_LAYER, i, enc_buffer[i]);
    }

    // 6. Encrypt data region [data_start, data_enc_end) in-place (no text mapping).
    const int data_start_block = data_start / WORDS_PER_BLOCK;
    const int data_end_block   = data_enc_end / WORDS_PER_BLOCK;
    for (int blk = data_start_block; blk < data_end_block; ++blk) {
        const int logical_addr = blk * WORDS_PER_BLOCK;
        uint32_t plain[WORDS_PER_BLOCK];
        for (int i = 0; i < WORDS_PER_BLOCK; ++i) plain[i] = stackedMemory.read(TARGET_LAYER, logical_addr + i);

        uint32_t cipher[WORDS_PER_BLOCK];
        aes_encrypt_block(plain, aes_key, cipher);
        for (int i = 0; i < WORDS_PER_BLOCK; ++i) {
            enc_buffer[logical_addr + i] = cipher[i];
        }
    }

    for (int i = data_start; i < data_enc_end; ++i) {
        stackedMemory.write(TARGET_LAYER, i, enc_buffer[i]);
    }

    int data_end = data_start + loaded_data;
    if (data_end > MEM_WORDS) data_end = MEM_WORDS;
    std::cout << "[INFO] Layout: KEY[0-" << (KEY_BLOCK_WORDS - 1)
              << "], TEXT_ENC[" << TEXT_START_ADDR << "-" << (text_enc_end - 1) << "]";
    if (loaded_data > 0) {
        std::cout << ", DATA_PLAIN[" << data_start << "-" << (data_end - 1) << "]";
        std::cout << ", DATA_ENC[" << data_start << "-" << (data_enc_end - 1) << "]";
    }
    std::cout << ", EPOCH=" << std::dec << mapping_epoch << std::endl;

    // 6. Hide key in block 0
    if (create_large_block_with_key(TARGET_LAYER, aes_key) != 0) {
        std::cerr << "[ERROR] Secure key wrapping failed." << std::endl;
        return 5;
    }
    if (secure_validate_image(TARGET_LAYER) != 0) {
        std::cerr << "[ERROR] Secure image sealing failed validation." << std::endl;
        return 6;
    }
    std::cout << "[INFO] Key stored as wrapped key + authenticated secure header on layer "
              << TARGET_LAYER << "." << std::endl;

    // 7. Debug: inspect block 0 and validate extracted key
    std::cout << "[DEBUG] Block 0 dump (layer 0):" << std::endl;
    for (int i = 0; i < 32; ++i) {
        uint32_t val = stackedMemory.protectedRead(TARGET_LAYER, i);
        std::cout << "L0[" << std::setw(2) << i << "] = 0x"
                  << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                  << val << std::endl;
    }
    uint32_t extracted_key[4] = {0, 0, 0, 0};
    if (extract_key_from_large_block(TARGET_LAYER, extracted_key) != 0) {
        std::cerr << "[ERROR] Could not extract app key from wrapped blob." << std::endl;
        return 7;
    }
    bool key_match = true;
    for (int i = 0; i < 4; ++i) {
        if (extracted_key[i] != aes_key[i]) {
            key_match = false;
        }
    }
    uint32_t extracted_key_fp = key_fingerprint(extracted_key);
    std::cout << "[DEBUG] Extracted app key fingerprint: 0x"
              << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << extracted_key_fp
              << std::dec << std::nouppercase << std::endl;
    if (!key_match) {
        std::cerr << "[ERROR] Wrapped blob unwrap mismatch." << std::endl;
        return 8;
    }
    std::cout << "[OK] Wrapped blob unwrap succeeded." << std::endl;

    // 8. Dump whole layer (1024 lines)
    std::ofstream fout(output_file);
    if (!fout) {
        std::cerr << "[ERROR] Cannot write " << output_file << "\n";
        return 1;
    }
    for (int i = 0; i < MEM_WORDS; ++i) {
        uint32_t v;
        if (i < 32)
            v = stackedMemory.protectedRead(TARGET_LAYER, i);
        else
            v = stackedMemory.read(TARGET_LAYER, i);
        fout << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << v << "\n";
    }
    fout.close();
    std::cout << "[INFO] Created demo image with 1024 lines." << std::endl;
    return 0;
}
