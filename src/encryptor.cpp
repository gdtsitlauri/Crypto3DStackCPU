#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include "3d.h"
#include "header.h"

extern StackedMemory3D stackedMemory;

namespace {

static constexpr uint32_t TARGET_LAYER      = 0u;
static constexpr uint32_t KEY_BLOCK_WORDS   = SEC_HDR_WORDS;
static constexpr uint32_t WORDS_PER_BLOCK   = INSTRS_PER_BLOCK;
static constexpr uint32_t TEXT_START_ADDR   = SEC_HDR_WORDS;
static constexpr uint32_t MAX_IMAGE_WORDS   = MEM_SIZE;

struct Options {
    std::string text_file;
    std::string data_file;
    std::string output_file;
    uint32_t epoch = 1u;
    bool epoch_provided = false;
    bool debug = false;
    bool deterministic_key = false;
    uint32_t deterministic_seed = 0u;
};

static void secure_zero_words(uint32_t *buf, size_t words) {
    volatile uint32_t *p = buf;
    for (size_t i = 0; i < words; ++i) {
        p[i] = 0u;
    }
}

static void secure_zero_bytes(uint8_t *buf, size_t bytes) {
    volatile uint8_t *p = buf;
    for (size_t i = 0; i < bytes; ++i) {
        p[i] = 0u;
    }
}

static uint32_t local_mix32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 15;
    x *= 0x846CA68Bu;
    x ^= x >> 16;
    return x;
}

static uint32_t key_fingerprint_debug_only(const uint32_t key[4]) {
    uint32_t fp = 0x6D5A56A9u;
    for (int i = 0; i < 4; ++i) {
        fp = local_mix32(fp ^ key[i] ^ (0x9E3779B9u * static_cast<uint32_t>(i + 1)));
    }
    return fp;
}

static std::string trim_copy(const std::string &s) {
    size_t first = 0;
    while (first < s.size() && (s[first] == ' ' || s[first] == '\t' || s[first] == '\r' || s[first] == '\n')) {
        ++first;
    }

    size_t last = s.size();
    while (last > first && (s[last - 1] == ' ' || s[last - 1] == '\t' || s[last - 1] == '\r' || s[last - 1] == '\n')) {
        --last;
    }

    return s.substr(first, last - first);
}

static std::string strip_comment_and_trim(const std::string &line) {
    size_t cut = std::string::npos;
    const size_t hash_pos = line.find('#');
    const size_t slash_pos = line.find("//");

    if (hash_pos != std::string::npos) {
        cut = hash_pos;
    }
    if (slash_pos != std::string::npos) {
        cut = (cut == std::string::npos) ? slash_pos : std::min(cut, slash_pos);
    }

    return trim_copy(cut == std::string::npos ? line : line.substr(0, cut));
}

static bool parse_u32(const std::string &s, uint32_t &out, int base = 0) {
    if (s.empty()) return false;

    char *endp = nullptr;
    errno = 0;
    unsigned long long v = std::strtoull(s.c_str(), &endp, base);

    if (errno != 0 || endp == s.c_str() || *endp != '\0') {
        return false;
    }
    if (v > std::numeric_limits<uint32_t>::max()) {
        return false;
    }

    out = static_cast<uint32_t>(v);
    return true;
}

static std::vector<uint32_t> read_hex_words_strict(const std::string &path, const char *label) {
    std::ifstream fin(path);
    if (!fin) {
        throw std::runtime_error(std::string("cannot open ") + label + " file: " + path);
    }

    std::vector<uint32_t> words;
    std::string line;
    uint32_t line_no = 0u;

    while (std::getline(fin, line)) {
        ++line_no;
        std::string token = strip_comment_and_trim(line);
        if (token.empty()) {
            continue;
        }

        uint32_t value = 0u;
        if (!parse_u32(token, value, 16)) {
            throw std::runtime_error(std::string("invalid hex word in ") + label + " file at line " + std::to_string(line_no));
        }
        words.push_back(value);
    }

    if (!fin.eof()) {
        throw std::runtime_error(std::string("failed while reading ") + label + " file: " + path);
    }

    return words;
}

static bool os_random_bytes(uint8_t *out, size_t len) {
    if (out == nullptr) return false;

#if defined(_WIN32)
    if (len == 0u) return true;
    NTSTATUS status = BCryptGenRandom(nullptr,
                                      reinterpret_cast<PUCHAR>(out),
                                      static_cast<ULONG>(len),
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return status >= 0;
#else
    int fd = ::open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;

    size_t done = 0u;
    while (done < len) {
        ssize_t n = ::read(fd, out + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            return false;
        }
        if (n == 0) {
            ::close(fd);
            return false;
        }
        done += static_cast<size_t>(n);
    }

    ::close(fd);
    return true;
#endif
}

static void generate_deterministic_test_key(uint32_t key[4], uint32_t seed) {
    uint32_t x = seed ? seed : 0xD1CEB00Cu;
    for (int i = 0; i < 4; ++i) {
        x = local_mix32(x ^ (0x9E3779B9u * static_cast<uint32_t>(i + 1)) ^ 0x43525054u);
        key[i] = x;
    }
    if ((key[0] | key[1] | key[2] | key[3]) == 0u) {
        key[0] = 0xA5A5A5A5u;
    }
}

static void generate_secure_app_key(uint32_t key[4], bool deterministic, uint32_t deterministic_seed) {
    if (deterministic) {
        generate_deterministic_test_key(key, deterministic_seed);
        return;
    }

    uint8_t raw[16];
    if (!os_random_bytes(raw, sizeof(raw))) {
        throw std::runtime_error("OS CSPRNG unavailable; refusing to generate a weak app key");
    }

    for (int i = 0; i < 4; ++i) {
        key[i] = (static_cast<uint32_t>(raw[i * 4 + 0]) << 24) |
                 (static_cast<uint32_t>(raw[i * 4 + 1]) << 16) |
                 (static_cast<uint32_t>(raw[i * 4 + 2]) << 8)  |
                 (static_cast<uint32_t>(raw[i * 4 + 3]));
    }

    secure_zero_bytes(raw, sizeof(raw));

    if ((key[0] | key[1] | key[2] | key[3]) == 0u) {
        // Astronomically unlikely, but avoid an all-zero AES key even if the OS
        // RNG returns a pathological output.
        key[0] = local_mix32(0xA5A5A5A5u);
        key[1] = local_mix32(0x3C6EF372u);
        key[2] = local_mix32(0xBB67AE85u);
        key[3] = local_mix32(0x510E527Fu);
    }
}

static uint32_t derive_auto_epoch(uint32_t text_words, uint32_t text_enc_end, uint32_t data_words, const uint32_t key[4]) {
    uint32_t x = 0x13579BDFu;
    x ^= text_words * 0x9E3779B9u;
    x ^= text_enc_end * 0x85EBCA6Bu;
    x ^= data_words * 0xC2B2AE35u;
    x ^= key[0] ^ local_mix32(key[1]) ^ local_mix32(key[2] ^ key[3]);
    x = local_mix32(x);
    return x ? x : 1u;
}

static uint32_t align_up_words(uint32_t value, uint32_t alignment) {
    if (alignment == 0u) return value;
    const uint32_t rem = value % alignment;
    if (rem == 0u) return value;
    return value + (alignment - rem);
}

static void print_usage(const char *prog) {
    std::cerr
        << "Usage: " << prog << " text.hex data.hex demo.hex [epoch] [--debug] [--deterministic-test-key=SEED]\n"
        << "\n"
        << "  epoch = 0 selects an automatic non-zero mapping epoch derived from the image.\n"
        << "  --debug prints non-secret diagnostics. It does not dump the secure header or key.\n"
        << "  --deterministic-test-key is for reproducible tests only; do not use for secure builds.\n";
}

static Options parse_args(int argc, char **argv) {
    if (argc < 4) {
        print_usage(argv[0]);
        throw std::runtime_error("missing required arguments");
    }

    Options opt;
    opt.text_file = argv[1];
    opt.data_file = argv[2];
    opt.output_file = argv[3];

    for (int i = 4; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--debug") {
            opt.debug = true;
            continue;
        }
        if (arg.rfind("--deterministic-test-key=", 0) == 0) {
            const std::string seed_s = arg.substr(std::strlen("--deterministic-test-key="));
            uint32_t seed = 0u;
            if (!parse_u32(seed_s, seed, 0)) {
                throw std::runtime_error("invalid deterministic key seed: " + seed_s);
            }
            opt.deterministic_key = true;
            opt.deterministic_seed = seed;
            continue;
        }
        if (arg == "--deterministic-test-key") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--deterministic-test-key requires a seed argument");
            }
            uint32_t seed = 0u;
            if (!parse_u32(argv[++i], seed, 0)) {
                throw std::runtime_error("invalid deterministic key seed");
            }
            opt.deterministic_key = true;
            opt.deterministic_seed = seed;
            continue;
        }

        if (!opt.epoch_provided) {
            uint32_t epoch = 0u;
            if (!parse_u32(arg, epoch, 0)) {
                throw std::runtime_error("invalid epoch or option: " + arg);
            }
            opt.epoch = epoch;
            opt.epoch_provided = true;
            continue;
        }

        throw std::runtime_error("unexpected argument: " + arg);
    }

    return opt;
}

static void reset_memory_to_known_state(uint32_t mem_words) {
    for (uint32_t i = 0; i < mem_words; ++i) {
        const uint32_t value = (i < KEY_BLOCK_WORDS) ? 0xDEADBEEFu : 0u;
        if (i < KEY_BLOCK_WORDS) {
            stackedMemory.protectedWrite(TARGET_LAYER, i, value);
        } else {
            stackedMemory.write(TARGET_LAYER, i, value);
        }
    }
}

static void write_plain_word(uint32_t addr, uint32_t value) {
    if (addr < KEY_BLOCK_WORDS) {
        stackedMemory.protectedWrite(TARGET_LAYER, addr, value);
    } else {
        stackedMemory.write(TARGET_LAYER, addr, value);
    }
}

static uint32_t read_plain_word(uint32_t addr) {
    return (addr < KEY_BLOCK_WORDS)
        ? stackedMemory.protectedRead(TARGET_LAYER, addr)
        : stackedMemory.read(TARGET_LAYER, addr);
}

static void encrypt_text_region_mapped(uint32_t text_start,
                                       uint32_t text_enc_end,
                                       const uint32_t app_key[4],
                                       uint32_t enc_buffer[MAX_IMAGE_WORDS]) {
    const uint32_t start_block = text_start / WORDS_PER_BLOCK;
    const uint32_t end_block   = text_enc_end / WORDS_PER_BLOCK;

    for (uint32_t i = 0u; i < MAX_IMAGE_WORDS; ++i) {
        enc_buffer[i] = read_plain_word(i);
    }

    for (uint32_t blk = start_block; blk < end_block; ++blk) {
        const uint32_t logical_addr = blk * WORDS_PER_BLOCK;
        if (logical_addr < KEY_BLOCK_WORDS) {
            throw std::runtime_error("text region overlaps secure header");
        }

        uint32_t plain[WORDS_PER_BLOCK] = {0u, 0u, 0u, 0u};
        uint32_t cipher[WORDS_PER_BLOCK] = {0u, 0u, 0u, 0u};

        for (uint32_t i = 0u; i < WORDS_PER_BLOCK; ++i) {
            plain[i] = read_plain_word(logical_addr + i);
        }

        aes_encrypt_block(plain, const_cast<uint32_t *>(app_key), cipher);

        const uint32_t phys_block = secure_map_text_block(blk);
        const uint32_t phys_addr = phys_block * WORDS_PER_BLOCK;
        if (phys_addr < KEY_BLOCK_WORDS || (phys_addr + WORDS_PER_BLOCK) > MAX_IMAGE_WORDS) {
            secure_zero_words(plain, WORDS_PER_BLOCK);
            secure_zero_words(cipher, WORDS_PER_BLOCK);
            throw std::runtime_error("invalid mapped text block address");
        }

        for (uint32_t i = 0u; i < WORDS_PER_BLOCK; ++i) {
            enc_buffer[phys_addr + i] = cipher[i];
        }

        secure_zero_words(plain, WORDS_PER_BLOCK);
        secure_zero_words(cipher, WORDS_PER_BLOCK);
    }

    for (uint32_t i = text_start; i < text_enc_end; ++i) {
        stackedMemory.write(TARGET_LAYER, i, enc_buffer[i]);
    }
}

static void encrypt_data_region_in_place(uint32_t data_start,
                                         uint32_t data_enc_end,
                                         const uint32_t app_key[4],
                                         uint32_t enc_buffer[MAX_IMAGE_WORDS]) {
    const uint32_t data_start_block = data_start / WORDS_PER_BLOCK;
    const uint32_t data_end_block   = data_enc_end / WORDS_PER_BLOCK;

    for (uint32_t i = 0u; i < MAX_IMAGE_WORDS; ++i) {
        enc_buffer[i] = read_plain_word(i);
    }

    for (uint32_t blk = data_start_block; blk < data_end_block; ++blk) {
        const uint32_t logical_addr = blk * WORDS_PER_BLOCK;
        if ((logical_addr + WORDS_PER_BLOCK) > MAX_IMAGE_WORDS) {
            throw std::runtime_error("data block exceeds memory size");
        }

        uint32_t plain[WORDS_PER_BLOCK] = {0u, 0u, 0u, 0u};
        uint32_t cipher[WORDS_PER_BLOCK] = {0u, 0u, 0u, 0u};

        for (uint32_t i = 0u; i < WORDS_PER_BLOCK; ++i) {
            plain[i] = read_plain_word(logical_addr + i);
        }

        aes_encrypt_block(plain, const_cast<uint32_t *>(app_key), cipher);

        for (uint32_t i = 0u; i < WORDS_PER_BLOCK; ++i) {
            enc_buffer[logical_addr + i] = cipher[i];
        }

        secure_zero_words(plain, WORDS_PER_BLOCK);
        secure_zero_words(cipher, WORDS_PER_BLOCK);
    }

    for (uint32_t i = data_start; i < data_enc_end; ++i) {
        stackedMemory.write(TARGET_LAYER, i, enc_buffer[i]);
    }
}

static void write_output_image(const std::string &output_file, uint32_t mem_words) {
    std::ofstream fout(output_file, std::ios::out | std::ios::trunc);
    if (!fout) {
        throw std::runtime_error("cannot write output file: " + output_file);
    }

    for (uint32_t i = 0u; i < mem_words; ++i) {
        const uint32_t v = read_plain_word(i);
        fout << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << v << '\n';
    }

    if (!fout) {
        throw std::runtime_error("failed while writing output file: " + output_file);
    }
}

static void verify_wrapped_key_roundtrip(const uint32_t expected_key[4], bool debug) {
    uint32_t extracted_key[4] = {0u, 0u, 0u, 0u};
    const int rc = extract_key_from_large_block(TARGET_LAYER, extracted_key);
    if (rc != 0) {
        secure_zero_words(extracted_key, 4);
        throw std::runtime_error("could not extract app key from wrapped secure header");
    }

    uint32_t diff = 0u;
    for (int i = 0; i < 4; ++i) {
        diff |= (extracted_key[i] ^ expected_key[i]);
    }

    if (debug) {
        std::cout << "[DEBUG] Wrapped-key self-test fingerprint: 0x"
                  << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                  << key_fingerprint_debug_only(extracted_key)
                  << std::dec << std::nouppercase << std::setfill(' ') << '\n';
    }

    secure_zero_words(extracted_key, 4);

    if (diff != 0u) {
        throw std::runtime_error("wrapped-key unwrap mismatch");
    }
}

} // namespace

int main(int argc, char **argv) {
    uint32_t app_key[4] = {0u, 0u, 0u, 0u};
    uint32_t enc_buffer[MAX_IMAGE_WORDS];
    for (uint32_t i = 0u; i < MAX_IMAGE_WORDS; ++i) {
        enc_buffer[i] = 0u;
    }

    try {
        const Options opt = parse_args(argc, argv);
        const uint32_t mem_words = static_cast<uint32_t>(stackedMemory.getNumWords());
        if (mem_words == 0u || mem_words > MAX_IMAGE_WORDS) {
            throw std::runtime_error("unexpected stacked-memory size");
        }
        if (KEY_BLOCK_WORDS != TEXT_START_ADDR) {
            throw std::runtime_error("internal layout mismatch");
        }

        std::vector<uint32_t> text_words = read_hex_words_strict(opt.text_file, "text");
        std::vector<uint32_t> data_words = read_hex_words_strict(opt.data_file, "data");

        if (text_words.empty()) {
            throw std::runtime_error("text image is empty");
        }

        reset_memory_to_known_state(mem_words);

        const uint32_t text_plain_words = static_cast<uint32_t>(text_words.size());
        const uint32_t text_plain_end = TEXT_START_ADDR + text_plain_words;
        const uint32_t text_enc_end = align_up_words(text_plain_end, WORDS_PER_BLOCK);

        if (text_plain_end < TEXT_START_ADDR || text_enc_end > mem_words) {
            throw std::runtime_error("text image does not fit in memory");
        }

        for (uint32_t i = 0u; i < text_plain_words; ++i) {
            write_plain_word(TEXT_START_ADDR + i, text_words[i]);
        }
        for (uint32_t i = text_plain_end; i < text_enc_end; ++i) {
            write_plain_word(i, 0u);
        }

        const uint32_t data_start = text_enc_end;
        const uint32_t data_plain_words = static_cast<uint32_t>(data_words.size());
        const uint32_t data_plain_end = data_start + data_plain_words;
        const uint32_t data_enc_end = align_up_words(data_plain_end, WORDS_PER_BLOCK);

        if (data_plain_end < data_start || data_enc_end > mem_words) {
            throw std::runtime_error("data image does not fit in memory after encrypted text region");
        }

        for (uint32_t i = 0u; i < data_plain_words; ++i) {
            write_plain_word(data_start + i, data_words[i]);
        }
        for (uint32_t i = data_plain_end; i < data_enc_end; ++i) {
            write_plain_word(i, 0u);
        }
        for (uint32_t i = data_enc_end; i < mem_words; ++i) {
            write_plain_word(i, 0u);
        }

        generate_secure_app_key(app_key, opt.deterministic_key, opt.deterministic_seed);

        uint32_t mapping_epoch = opt.epoch;
        if (mapping_epoch == 0u) {
            mapping_epoch = derive_auto_epoch(text_plain_words, text_enc_end, data_plain_words, app_key);
        }
        if (mapping_epoch == 0u) {
            mapping_epoch = 1u;
        }

        secure_set_image_region(TEXT_START_ADDR, text_plain_words, text_enc_end);
        secure_set_data_region(data_start, data_plain_words, data_enc_end, SEC_DATA_FLAG_ENCRYPTED);
        secure_set_mapping_epoch(mapping_epoch);

        encrypt_text_region_mapped(TEXT_START_ADDR, text_enc_end, app_key, enc_buffer);
        encrypt_data_region_in_place(data_start, data_enc_end, app_key, enc_buffer);

        const int seal_rc = create_large_block_with_key(TARGET_LAYER, app_key);
        if (seal_rc != 0) {
            throw std::runtime_error("secure key wrapping/header sealing failed with rc=" + std::to_string(seal_rc));
        }

        const int validate_rc = secure_validate_image(TARGET_LAYER);
        if (validate_rc != 0) {
            throw std::runtime_error("secure image validation failed with rc=" + std::to_string(validate_rc));
        }

        verify_wrapped_key_roundtrip(app_key, opt.debug);
        write_output_image(opt.output_file, mem_words);

        std::cout << "[OK] Created sealed image: " << opt.output_file << '\n'
                  << "[INFO] Layout: HEADER[0-" << (KEY_BLOCK_WORDS - 1u) << "], "
                  << "TEXT_ENC[" << TEXT_START_ADDR << '-' << (text_enc_end ? text_enc_end - 1u : 0u) << "], ";
        if (data_plain_words > 0u) {
            std::cout << "DATA_ENC[" << data_start << '-' << (data_enc_end - 1u) << "], ";
        } else {
            std::cout << "DATA_ENC[empty], ";
        }
        std::cout << "EPOCH=" << mapping_epoch << '\n';

        if (opt.deterministic_key) {
            std::cout << "[WARN] Deterministic test key was used. Do not use this image as a secure artifact.\n";
        } else {
            std::cout << "[INFO] App key generated with OS CSPRNG; key material was not printed.\n";
        }

        if (opt.debug) {
            std::cout << "[DEBUG] App-key fingerprint: 0x"
                      << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                      << key_fingerprint_debug_only(app_key)
                      << std::dec << std::nouppercase << std::setfill(' ') << '\n';
        }

        secure_zero_words(app_key, 4);
        secure_zero_words(enc_buffer, MAX_IMAGE_WORDS);
        return 0;
    } catch (const std::exception &ex) {
        secure_zero_words(app_key, 4);
        secure_zero_words(enc_buffer, MAX_IMAGE_WORDS);
        std::cerr << "[ERROR] " << ex.what() << '\n';
        return 1;
    }
}
