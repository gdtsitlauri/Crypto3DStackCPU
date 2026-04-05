#include <iostream>
#include <iomanip>
#include <cstdint>
#include "3d.h"
#include "header.h"
#include <fstream>
#include <vector>

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

int main(int argc, char **argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " encrypted.hex output.hex\n";
        std::cerr << "   or: " << argv[0] << " encrypted.hex reference_text.hex output.hex\n";
        return 1;
    }
    std::string input_file  = argv[1];
    std::string reference_file;
    std::string output_file;

    if (argc >= 4) {
        reference_file = (std::string(argv[2]) == "-") ? "" : argv[2];
        output_file = argv[3];
    } else {
        output_file = argv[2];
    }

    const int TARGET_LAYER = 0;
    const int MEM_WORDS    = static_cast<int>(stackedMemory.getNumWords());
    static constexpr int WORDS_PER_BLOCK = 4;

    // 1. Reset whole layer 0 to DEADBEEF
    for (int i = 0; i < MEM_WORDS; ++i) stackedMemory.write(TARGET_LAYER, i, 0xDEADBEEF);

    // 2. Load encrypted.hex in layer 0 (block 0 + encrypted text)
    std::ifstream fin(input_file);
    if (!fin) {
        std::cerr << "[ERROR] Cannot open input file: " << input_file << "\n";
        return 1;
    }
    int loaded_lines = 0;
    std::string line;
    int mem_addr = 0;
    while (mem_addr < MEM_WORDS && std::getline(fin, line)) {
        uint32_t val = 0;
        if (!line.empty()) {
            try { val = std::stoul(line, nullptr, 16); } catch (...) { val = 0; }
        }
        stackedMemory.write(TARGET_LAYER, mem_addr, val);
        mem_addr++;
        loaded_lines++;
    }
    fin.close();
    std::cout << "[INFO] Loaded encrypted file: " << input_file << " (" << loaded_lines << " lines)" << std::endl;

    // 3. Validate authenticated image before key extraction/decryption.
    if (secure_validate_image(TARGET_LAYER) != 0) {
        std::cerr << "[ERROR] Secure image validation failed. Refusing to decrypt." << std::endl;
        return 2;
    }

    // 4. Extract key from secure header + hidden map
    uint32_t aes_key[4] = {0, 0, 0, 0};
    if (extract_key_from_large_block(TARGET_LAYER, aes_key) != 0) {
        std::cerr << "[ERROR] Could not unwrap app key from secure image." << std::endl;
        return 3;
    }
    uint32_t key_fp = key_fingerprint(aes_key);
    std::cout << "[INFO] Extracted app key fingerprint: 0x"
              << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << key_fp
              << std::dec << std::nouppercase << std::endl;

    uint32_t text_start = 0;
    uint32_t text_words = 0;
    uint32_t text_end = 0;
    uint32_t epoch = 0;
    if (secure_get_image_region(&text_start, &text_words, &text_end, &epoch) != 0) {
        std::cerr << "[ERROR] Could not read secure image metadata." << std::endl;
        return 4;
    }

    uint32_t text_plain_end = text_start + text_words;
    if (text_plain_end > (uint32_t)MEM_WORDS) text_plain_end = (uint32_t)MEM_WORDS;
    if (text_end > (uint32_t)MEM_WORDS) text_end = (uint32_t)MEM_WORDS;

    std::cout << "[INFO] Header region: text_start=" << std::dec << text_start
              << ", text_words=" << text_words
              << ", text_end=" << text_end
              << ", epoch=" << epoch << std::endl;

    const uint32_t start_block = text_start / WORDS_PER_BLOCK;
    const uint32_t end_block   = text_end / WORDS_PER_BLOCK;
    std::vector<uint32_t> plain_words((text_plain_end > text_start) ? (text_plain_end - text_start) : 0u, 0u);

    for (uint32_t blk = start_block; blk < end_block; ++blk) {
        uint32_t phys_blk = secure_map_text_block(blk);
        uint32_t phys_addr = phys_blk * WORDS_PER_BLOCK;
        if ((phys_addr + WORDS_PER_BLOCK) > (uint32_t)MEM_WORDS) {
            std::cerr << "[ERROR] Invalid mapped block while decrypting." << std::endl;
            return 5;
        }

        uint32_t cipher[WORDS_PER_BLOCK];
        for (int i = 0; i < WORDS_PER_BLOCK; ++i) cipher[i] = stackedMemory.read(TARGET_LAYER, phys_addr + (uint32_t)i);
        uint32_t plain[WORDS_PER_BLOCK];
        aes_decrypt_block(cipher, aes_key, plain);

        uint32_t logical_addr = blk * WORDS_PER_BLOCK;
        for (int i = 0; i < WORDS_PER_BLOCK; ++i) {
            uint32_t la = logical_addr + (uint32_t)i;
            if (la >= text_start && la < text_plain_end) {
                plain_words[la - text_start] = plain[i];
            }
        }
    }

    // 6. Dump only decrypted plain text words.
    std::ofstream fout(output_file);
    if (!fout) {
        std::cerr << "[ERROR] Cannot write to " << output_file << "\n";
        return 1;
    }
    for (size_t i = 0; i < plain_words.size(); ++i) {
        uint32_t v = plain_words[i];
        fout << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << v << "\n";
    }
    fout.close();
    std::cout << "[INFO] Decryption complete. Written " << plain_words.size()
              << " lines to " << output_file << std::endl;

    if (!reference_file.empty()) {
        std::ifstream fref(reference_file);
        if (!fref) {
            std::cerr << "[WARN] Could not open reference file: " << reference_file << std::endl;
            return 0;
        }

        size_t idx = 0;
        size_t mismatches = 0;
        while (std::getline(fref, line)) {
            uint32_t ref = 0;
            if (!line.empty()) {
                try { ref = std::stoul(line, nullptr, 16); } catch (...) { ref = 0; }
            }
            uint32_t got = (idx < plain_words.size()) ? plain_words[idx] : 0;
            if (ref != got) mismatches++;
            idx++;
        }
        std::cout << "[INFO] Reference compare mismatches=" << std::dec << mismatches << std::endl;
    }

    return 0;
}
